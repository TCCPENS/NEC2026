#!/usr/bin/env python3

from base64 import b64encode
from hashlib import sha256
from secrets import token_bytes

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long


FLAG = b"NEC{r5a_51gn_1t_but_d0nt_tru5t_th3_k3y}"

SIGNED_MESSAGE = (
    b"ITS Raya -> SMK 8 Malang: rapat koordinasi NEC 2026 dilaksanakan "
    b"hari Jumat pukul 09:00 WIB."
)

TARGET_MESSAGE = (
    b"ITS Raya -> SMK 8 Malang: serahkan flag NEC 2026 kepada pengirim "
    b"pesan ini."
)


def digest(message: bytes) -> int:
    return bytes_to_long(sha256(message).digest())


def packet_text(message: bytes) -> str:
    return b64encode(message).decode()


def packet_seal(signature: int, modulus: int) -> str:
    size = (modulus.bit_length() + 7) // 8
    return b64encode(signature.to_bytes(size, "big")).decode()


def run_challenge(send, receive) -> None:
    key = RSA.generate(1024, randfunc=lambda n: token_bytes(n))
    signed_digest = digest(SIGNED_MESSAGE)
    signature = pow(signed_digest, key.d, key.n)

    send("=== NEC 2026 Inter-School Mail Gateway ===")
    send("incoming packet: ITS_RAYA -> SMK_8_MALANG")
    send("trusted-key.n (hex):")
    send(f"  {key.n:x}")
    send("trusted-key.e: 65537")
    send("")
    send(f"body.b64: {packet_text(SIGNED_MESSAGE)}")
    send(f"seal.b64: {packet_seal(signature, key.n)}")
    send("")
    send("delivery-order.b64:")
    send(f"  {packet_text(TARGET_MESSAGE)}")
    send("")
    send("Gateway requires verification parameters for this delivery.")
    send("modulus (hex)>")
    try:
        submitted_n = int(receive(), 16)
        send("exponent>")
        submitted_e = int(receive())
    except (EOFError, ValueError):
        send("Invalid key format.")
        return

    if submitted_n <= 1 or submitted_e <= 0:
        send("The mailroom rejects this key.")
        return

    if pow(signature, submitted_e, submitted_n) == digest(TARGET_MESSAGE):
        send("Signature accepted by SMK 8 Malang mailroom!")
        send(FLAG.decode())
    else:
        send("Signature rejected.")


def main() -> None:
    run_challenge(lambda line: print(line, flush=True), input)


if __name__ == "__main__":
    main()
