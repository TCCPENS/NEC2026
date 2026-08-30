#!/usr/bin/env python3

import os
import socket
import subprocess
import threading

HOST = "0.0.0.0"
PORT = 31337


def serve_client(client: socket.socket) -> None:
    process = subprocess.Popen(
        ["/app/signal_recovery"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    def forward_output() -> None:
        try:
            while True:
                # os.read returns currently available pipe data; BufferedReader
                # may wait for the full requested size and hide the prompt.
                data = os.read(process.stdout.fileno(), 4096)
                if not data:
                    break
                client.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    output_thread = threading.Thread(target=forward_output, daemon=True)
    output_thread.start()

    try:
        while True:
            data = client.recv(4096)
            if not data:
                break
            process.stdin.write(data)
            process.stdin.flush()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        output_thread.join(timeout=1)
        client.close()


def main() -> None:
    port = int(os.environ.get("PORT", PORT))
    with socket.create_server((HOST, port), reuse_port=False) as server:
        while True:
            client, _ = server.accept()
            threading.Thread(target=serve_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
