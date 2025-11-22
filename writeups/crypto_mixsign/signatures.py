from ecdsa.curves import SECP256k1

import hashlib
import gmpy2
import os

p = SECP256k1.curve.p()
G = SECP256k1.generator
n = int(G.order())

def generate_keys():
    seckey = int.from_bytes(os.urandom(64)) % n
    pubkey = seckey * G
    return seckey, pubkey

def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + msg).digest()

def bytes_from_int(x: int) -> bytes:
    return int(x).to_bytes(32, byteorder="big")

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def schnorr_sign(msg: bytes, seckey: bytes) -> bytes:
    d = seckey
    if not (1 <= d <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    
    P = d * G
    assert P is not None
    
    k = int_from_bytes(tagged_hash("nonce", bytes_from_int(d) + P.to_bytes() + msg)) % n
    if k == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = k*G
    assert R.x() is not None

    e = int_from_bytes(tagged_hash("challenge", R.to_bytes()[0:32] + P.to_bytes() + msg)) % n
    sig = R.to_bytes()[0:32] + bytes_from_int((k + e * d) % n)

    if not schnorr_verify(msg, P, sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def schnorr_verify(msg, pubkey, sig) -> bool:
    if len(sig) != 64:
        raise ValueError('The signature must be 64 bytes.')

    if pubkey.x() == None:
        return False

    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (r >= p) or (s >= n):
        return False
    e = int_from_bytes(tagged_hash("challenge", sig[0:32] + pubkey.to_bytes() + msg)) % n
    R = s*G + (n - e) * pubkey

    if (R.x() is None) or (R.x() != r):
        return False

    return True

def ecdsa_sign(msg: bytes, seckey: bytes) -> bytes:
    d = seckey
    if not (1 <= d <= n - 1):
        raise ValueError('The secret key must be an integer in the range 1..n-1.')
    
    P = d * G
    assert P is not None
    
    k = int_from_bytes(tagged_hash("nonce", bytes_from_int(d) + P.to_bytes() + msg)) % n
    if k == 0:
        raise RuntimeError('Failure. This happens only with negligible probability.')
    R = k*G
    r = R.x()
    assert r is not None

    z = int_from_bytes(tagged_hash("challenge", msg)) % n
    sig = bytes_from_int(r) + bytes_from_int(gmpy2.invert(k, n) * (z + r * d) % n)

    if not ecdsa_verify(msg, P, sig):
        raise RuntimeError('The created signature does not pass verification.')
    return sig

def ecdsa_verify(msg, pubkey, sig) -> bool:
    if len(sig) != 64:
        raise ValueError('The signature must be a 64-byte array.')

    if pubkey.x() == None:
        return False

    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if (r >= p) or (s >= n):
        return False
    z = int_from_bytes(tagged_hash("challenge", msg)) % n
    R = z * gmpy2.invert(s, n)*G + r * gmpy2.invert(s, n) * pubkey

    if (R.x() is None) or (R.x() != r):
        return False

    return True
