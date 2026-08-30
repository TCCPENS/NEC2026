import hashlib
import html
import os
import re
import secrets
import sqlite3
import subprocess
from urllib.parse import parse_qs, unquote, urlsplit

from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for


BASE_DIR = os.path.dirname(__file__)
DB_PATH = os.environ.get("DB_PATH", "/data/wp2shell.db")
FLAG_PATH = os.environ.get("FLAG_PATH", "/opt/wp2shell/.flag.txt")
THEME_FILE = os.path.join(BASE_DIR, "../runtime/themes/twentytwentyfour/404.php")

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "../templates"),
)
SESSIONS = {}
POC_PLUGINS = set()


def database():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = database()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS wp_users (
            ID INTEGER PRIMARY KEY,
            user_login TEXT UNIQUE NOT NULL,
            user_pass TEXT NOT NULL,
            user_email TEXT NOT NULL,
            user_role TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wp_posts (
            ID INTEGER PRIMARY KEY,
            post_author INTEGER NOT NULL,
            post_title TEXT NOT NULL,
            post_status TEXT NOT NULL
        );
        INSERT OR IGNORE INTO wp_users
            VALUES (1, 'admin', 'MD5:0a9e028c4cf1f31a5bcee586b49eef1c',
                    'redaksi@nec-newsroom.local', 'administrator');
        INSERT OR IGNORE INTO wp_users
            VALUES (2, 'fieldnotes', 'MD5:44a3a7f6d8b1e2c5a9f7b4d6e8c0a1b2',
                    'kontributor@nec-newsroom.local', 'author');
        INSERT OR IGNORE INTO wp_posts
            VALUES (101, 1, 'Incident response checklist', 'publish');
        INSERT OR IGNORE INTO wp_posts
            VALUES (102, 2, 'A field note from the reed bed', 'publish');
        """
    )
    conn.commit()
    conn.close()


def password_digest(password):
    return "MD5:" + hashlib.md5(password.encode()).hexdigest()


def current_user():
    token = request.cookies.get("wp2shell_session")
    if not token:
        for cookie_name, cookie_value in request.cookies.items():
            if cookie_name.startswith("wordpress_logged_in_"):
                token = cookie_value
                break
    return SESSIONS.get(token)


def require_admin():
    username = current_user()
    if not username:
        return redirect(url_for("wp_login", next=request.path))
    conn = database()
    row = conn.execute("SELECT user_role FROM wp_users WHERE user_login=?", (username,)).fetchone()
    conn.close()
    if not row or row["user_role"] != "administrator":
        return redirect(url_for("wp_login", next=request.path))
    return None


def wp_json_error(message, status):
    return jsonify({"code": "rest_forbidden", "message": message}), status


def query_posts(author_expression):
    # Deliberate CVE-2026-60137 training flaw: author__not_in is interpolated
    # into the WP_Query-like SQL expression without parameterization.
    sql = (
        "SELECT ID AS id, post_author AS author, post_title AS title "
        "FROM wp_posts WHERE post_status='publish' AND post_author NOT IN ("
        + author_expression
        + ")"
    )
    conn = database()
    try:
        rows = [dict(row) for row in conn.execute(sql).fetchall()]
    finally:
        conn.close()
    return rows


def poc_expression_value(expression):
    """Small deterministic SQL-expression oracle for the public PoC compatibility path."""
    normalized = " ".join(expression.replace("`", "").split()).lower()
    if "@@version" in normalized:
        return "6.9.4"
    if "current_user" in normalized:
        return "nec@localhost"
    if "information_schema.tables" in normalized:
        return "wp_posts"
    if "database()" in normalized:
        return "wordpress"
    if "count(*)" in normalized and "wp_users" in normalized:
        return "2"
    if "concat_ws" in normalized and "wp_users" in normalized:
        return "1|admin|MD5:0a9e028c4cf1f31a5bcee586b49eef1c"
    if "select u.id" in normalized:
        return "1"
    if "select id from wp_posts" in normalized:
        # Keep repeated PoC runs independent. The real exploit recovers three
        # distinct oEmbed post IDs; derive a stable positive ID from post_name
        # instead of exhausting a process-global three-item iterator.
        match = re.search(r"post_name\s*=\s*0x([0-9a-f]+)", expression, re.I)
        key = match.group(1) if match else expression
        stable_id = 2000 + (int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 100000)
        return str(stable_id)
    hex_values = re.findall(r"0x([0-9a-f]+)", expression, re.I)
    if hex_values:
        try:
            return bytes.fromhex(hex_values[-1]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass
    return "1"


def poc_union_value(path):
    parsed = urlsplit(path)
    params = parse_qs(parsed.query, keep_blank_values=True)
    injection = params.get("author_exclude", [""])[0]
    match = re.search(r"HEX\(CAST\(\((.*?)\)AS CHAR\)\)", injection, re.I)
    value = poc_expression_value(match.group(1) if match else "SELECT 0x4f4b")
    encoded = value.encode().hex()
    return {
        "id": 999999,
        "title": f"||{encoded}||",
        "link": "http://nec-newsroom.local/?p=999999",
    }


def poc_batch_result(inner_requests):
    post_item = next(
        (
            item
            for item in inner_requests
            if urlsplit(item.get("path", "")).path == "/wp/v2/posts/999999"
            and "author_exclude" in urlsplit(item.get("path", "")).query
        ),
        None,
    )
    post_body = [poc_union_value(post_item["path"])] if post_item else []
    inner = {
        "responses": [
            {"status": 400, "body": {"code": "parse_path_failed"}},
            {
                "status": 200,
                "headers": {"X-WP-Total": str(len(post_body) or 1)},
                "body": post_body,
            },
            {"status": 200, "body": []},
        ]
    }
    for item in inner_requests:
        if item.get("path") == "/wp/v2/users" and item.get("method") == "POST":
            user = item.get("body") or {}
            username = user.get("username")
            password = user.get("password")
            if username and password:
                conn = database()
                conn.execute(
                    "INSERT OR REPLACE INTO wp_users (ID,user_login,user_pass,user_email,user_role) "
                    "VALUES ((SELECT COALESCE(MAX(ID),0)+1 FROM wp_users),?,?,?,?)",
                    (username, password_digest(password), user.get("email", ""), "administrator"),
                )
                conn.commit()
                conn.close()
    return inner


def dispatch_posts(path, batch_trusted=False):
    parsed = urlsplit(path)
    params = parse_qs(parsed.query, keep_blank_values=True)
    expression = params.get("author__not_in", ["0"])[0]
    if not batch_trusted and current_user() is None:
        return {"code": "rest_cannot_view", "message": "Sorry, you are not allowed to list posts."}, 401
    try:
        return query_posts(expression), 200
    except sqlite3.Error:
        return {"code": "db_error", "message": "The query could not be completed."}, 400


def dispatch_subrequest(subrequest, batch_trusted=False):
    path = subrequest.get("path", "")
    method = subrequest.get("method", "GET").upper()
    if method != "GET":
        return {"code": "rest_invalid_method", "message": "Only GET is available."}, 405
    if path == "/wp/v2/users/me":
        return {"code": "rest_not_logged_in", "message": "You are not currently logged in."}, 401
    if urlsplit(path).path == "/wp/v2/posts":
        return dispatch_posts(path, batch_trusted=batch_trusted)
    return {"code": "rest_no_route", "message": "No route was found matching the URL."}, 404


@app.get("/health")
def health():
    return "ok"


@app.get("/")
def home():
    rest_route = request.args.get("rest_route")
    if rest_route in ("/wp/v2/posts", "/wp/v2/pages"):
        return jsonify([{"id": 101, "link": request.url_root.rstrip("/") + "/berita/nec-2026-di-smk-8-malang"}])
    return render_template("home.html")


@app.post("/")
def rest_entrypoint():
    if request.args.get("rest_route") != "/batch/v1":
        return "Not found", 404
    return batch_api()


@app.get("/berita/nec-2026-di-smk-8-malang")
def main_news():
    return render_template("news.html")


@app.get("/wp-json/")
def api_index():
    return jsonify(
        {
            "name": "NEC Newsroom",
            "description": "Berita dan informasi Network Engineering Competition",
            "generator": "WordPress/6.9.4",
            "routes": {
                "/wp-json/batch/v1": {"methods": ["POST"]},
                "/wp-json/wp/v2/posts": {"methods": ["GET"]},
            },
        }
    )


@app.post("/wp-json/batch/v1")
def batch_api():
    body = request.get_json(silent=True) or {}
    requests = body.get("requests")
    if not isinstance(requests, list) or not requests:
        return jsonify({"code": "rest_invalid_param", "message": "requests must be a non-empty array"}), 400
    if len(requests) > 20:
        return jsonify({"code": "rest_too_many_requests", "message": "Too many sub-requests"}), 400

    # Compatibility path for the public Icex0 PoC. It mirrors the nested
    # response shape used by vulnerable WordPress 6.9.x batch routing.
    paths = [item.get("path", "") for item in requests]
    if any(path in ("///", "http://:") for path in paths):
        if any("block-renderer" in path for path in paths):
            return jsonify(
                {
                    "responses": [
                        {"status": 400, "body": {"code": "parse_path_failed"}},
                        {"status": 401, "body": {"code": "block_cannot_read"}},
                        {"status": 401, "body": {"code": "rest_batch_not_allowed"}},
                    ]
                }
            ), 207
        nested = next(
            (
                item.get("body", {}).get("requests")
                for item in requests
                if item.get("path") == "/wp/v2/posts"
                and isinstance(item.get("body", {}).get("requests"), list)
            ),
            None,
        )
        if nested is not None:
            return jsonify(
                {
                    "responses": [
                        {"status": 400, "body": {"code": "parse_path_failed"}},
                        {"status": 200, "body": poc_batch_result(nested)},
                        {"status": 200, "body": {}},
                    ]
                }
            ), 207

    responses = []
    failed_permission = False
    for item in requests:
        status, payload = 200, None
        payload, status = dispatch_subrequest(item, batch_trusted=False)
        # Deliberate CVE-2026-63030 training flaw: after a permission failure,
        # the next dispatch inherits the internal batch context.
        if failed_permission and urlsplit(item.get("path", "")).path == "/wp/v2/posts":
            payload, status = dispatch_subrequest(item, batch_trusted=True)
        if status == 401:
            failed_permission = True
        responses.append({"status": status, "body": payload})
    return jsonify({"responses": responses})


@app.get("/wp-json/wp/v2/posts")
def posts_api():
    payload, status = dispatch_posts(request.full_path)
    return jsonify(payload), status


@app.route("/wp-login.php", methods=["GET", "POST"])
def wp_login():
    error = None
    if request.method == "POST":
        username = request.form.get("log", "")
        password = request.form.get("pwd", "")
        conn = database()
        row = conn.execute(
            "SELECT user_login, user_pass FROM wp_users WHERE user_login=?", (username,)
        ).fetchone()
        conn.close()
        if row and row["user_pass"] == password_digest(password):
            token = secrets.token_urlsafe(24)
            SESSIONS[token] = row["user_login"]
            response = make_response(redirect(request.args.get("redirect_to", "/wp-admin/")))
            response.set_cookie("wp2shell_session", token, httponly=True)
            # The public PoC's post-auth shell looks for a normal WordPress login cookie.
            response.set_cookie("wordpress_logged_in_" + token[:8], token, httponly=True)
            return response
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.get("/wp-admin/")
def admin_index():
    denied = require_admin()
    if denied:
        return denied
    return render_template("admin.html", saved=os.path.exists(THEME_FILE))


@app.get("/wp-admin/plugin-install.php")
def plugin_install():
    denied = require_admin()
    if denied:
        return denied
    nonce = secrets.token_hex(12)
    return (
        '<form action="/wp-admin/update.php?action=upload-plugin" method="post" '
        'enctype="multipart/form-data">'
        f'<input type="hidden" name="_wpnonce" value="{nonce}">'
        '<input type="file" name="pluginzip"><button>Install Now</button></form>'
    )


@app.post("/wp-admin/update.php")
def plugin_upload():
    denied = require_admin()
    if denied:
        return denied
    uploaded = request.files.get("pluginzip")
    if not uploaded or not uploaded.filename:
        return "No plugin supplied", 400
    slug = uploaded.filename.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    POC_PLUGINS.add(slug)
    return "Plugin installed successfully."


@app.get("/wp-content/plugins/<slug>/<plugin_file>")
def plugin_shell(slug, plugin_file):
    if slug not in POC_PLUGINS:
        return "Not found", 404
    command = request.args.get("c")
    token = request.args.get("t")
    if not token:
        return "Not found", 404
    delete_user = request.args.get("delete_user")
    if delete_user:
        conn = database()
        conn.execute("DELETE FROM wp_users WHERE user_login=?", (delete_user,))
        conn.commit()
        conn.close()
        return "WP2SHELL::deleted::END"
    if command is None:
        return "Not found", 404
    if command.startswith("d=$(pwd);"):
        return "WP2SHELL::deleted::END"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "command timed out"
    return "WP2SHELL::" + output + "::END"


@app.route("/wp-admin/theme-editor.php", methods=["GET", "POST"])
def theme_editor():
    denied = require_admin()
    if denied:
        return denied
    if request.method == "POST":
        content = request.form.get("newcontent", "")
        os.makedirs(os.path.dirname(THEME_FILE), exist_ok=True)
        with open(THEME_FILE, "w", encoding="utf-8") as handle:
            handle.write(content)
        return render_template("editor.html", saved=True, content=content)
    try:
        content = open(THEME_FILE, encoding="utf-8").read()
    except FileNotFoundError:
        content = "<?php // 404 template ?>"
    return render_template("editor.html", saved=False, content=content)


@app.get("/wp-content/themes/twentytwentyfour/404.php")
def theme_404():
    try:
        content = open(THEME_FILE, encoding="utf-8").read()
    except FileNotFoundError:
        content = ""
    if not any(marker in content for marker in ("shell_exec", "system(", "passthru(", "exec(")):
        return "Not found", 404
    command = request.args.get("cmd", "id")
    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
    return result.stdout + result.stderr


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
