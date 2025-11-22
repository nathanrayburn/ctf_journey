#!/usr/bin/env python3
"""
Recover a private key when the same nonce was reused across Schnorr and ECDSA.

Plug in the public key, both signatures, and the message that was signed.
"""

import sys

import gmpy2

from signatures import (
    G,
    bytes_from_int,
    int_from_bytes,
    n,
    tagged_hash,
)


def recover_key(pub_hex: str, schnorr_hex: str, ecdsa_hex: str, msg: bytes) -> int:
    pub_bytes = bytes.fromhex(pub_hex)
    schnorr_bytes = bytes.fromhex(schnorr_hex)
    ecdsa_bytes = bytes.fromhex(ecdsa_hex)

    r_bytes = schnorr_bytes[:32]
    if r_bytes != ecdsa_bytes[:32]:
        raise ValueError("Nonce point x-coordinates differ; nonce not reused.")

    r = int_from_bytes(r_bytes)
    s1 = int_from_bytes(ecdsa_bytes[32:])      # ECDSA s
    s2 = int_from_bytes(schnorr_bytes[32:])    # Schnorr s

    z = int_from_bytes(tagged_hash("challenge", msg)) % n
    e = int_from_bytes(tagged_hash("challenge", r_bytes + pub_bytes + msg)) % n

    numer = (s1 * s2 - z) % n
    den = (r + s1 * e) % n
    inv_den = int(gmpy2.invert(den, n))
    return int((numer * inv_den) % n)


def main():
    pub_hex = "a37b97df0c5a0f70b978fd3f1732ce0241a57141be19219437eacc5a6d26dbedcd1570705e2b053b247f9f2e9e0aea64a1aa5ebd50bd2164ad47875dc3da186d"
    schnorr_hex = "7d84d017ed925d7858454b0ba10870ad02cb65855c7e8e3618a71f84d00f5c59dba379ac3cce807f94cb106c47a0e89240b84cf9ea50c8fa5dfb0880aca8a143"
    ecdsa_hex = "7d84d017ed925d7858454b0ba10870ad02cb65855c7e8e3618a71f84d00f5c59112458fb74f6936aa87282dcb359ea6502a1033d660dd8ee8036799ee1d18303"
    msg = b"test"

    priv = recover_key(pub_hex, schnorr_hex, ecdsa_hex, msg)
    print(f"Recovered private key: {priv:064x}")

    # Quick self-check: recompute the public key to confirm it matches.
    pub_check = (priv * G).to_bytes().hex()
    print(f"Derived public key  : {pub_check}")
    print(f"Original public key : {pub_hex}")
    if pub_check != pub_hex:
        sys.exit("Public key mismatch; recovery failed.")


if __name__ == "__main__":
    main()
