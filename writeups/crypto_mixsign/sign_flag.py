#!/usr/bin/env python3
"""
Generate valid signatures on the message "Flag please" using the recovered key.
"""

from signatures import ecdsa_sign, schnorr_sign

SECKEY_HEX = "d29e7bcd33effaa474e8de3aea40209d5859dee12e860b2b727f188dad37ada7"
MESSAGE = b"Flag please"


def main() -> None:
    seckey = int(SECKEY_HEX, 16)
    ecdsa_sig = ecdsa_sign(MESSAGE, seckey).hex()
    schnorr_sig = schnorr_sign(MESSAGE, seckey).hex()

    print(f"Message: {MESSAGE.decode()}")
    print(f"ECDSA signature : {ecdsa_sig}")
    print(f"Schnorr signature: {schnorr_sig}")


if __name__ == "__main__":
    main()
