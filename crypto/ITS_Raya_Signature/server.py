#!/usr/bin/env python3

import os
import socket
import threading

from chall import run_challenge


HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "1337"))


def handle_client(connection: socket.socket, address) -> None:
    print(f"[+] connection from {address[0]}:{address[1]}")
    reader = connection.makefile("r", encoding="utf-8", newline="\n")
    writer = connection.makefile("w", encoding="utf-8", newline="\n")

    def send(line: str) -> None:
        writer.write(line + "\n")
        writer.flush()

    def receive() -> str:
        line = reader.readline()
        if line == "":
            raise EOFError
        return line.strip()

    try:
        run_challenge(send, receive)
    except (BrokenPipeError, ConnectionResetError, EOFError):
        print(f"[-] connection closed: {address[0]}:{address[1]}")
    finally:
        reader.close()
        writer.close()
        connection.close()


def main() -> None:
    with socket.create_server((HOST, PORT), reuse_port=False) as server:
        print(f"[*] ITS Raya Signature listening on {HOST}:{PORT}")
        while True:
            connection, address = server.accept()
            threading.Thread(
                target=handle_client,
                args=(connection, address),
                daemon=True,
            ).start()


if __name__ == "__main__":
    main()
