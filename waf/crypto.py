import os
import json
import base64
import hashlib
import binascii

from aesgcm.python_aesgcm import new as aesgcm_new

KEY = bytes.fromhex(
    "6f71a512b1e035eaab53d8be73120d3fb68a0ca346b9560aab3e5cdf753d5e98"
)


def encode(obj: dict) -> str:
    raw = json.dumps(obj, separators=(",", ":"))
    crc = binascii.crc32(raw.encode()) & 0xFFFFFFFF
    return f"{crc:08X}#{raw}"


def encrypt(plaintext: str) -> str:
    iv     = os.urandom(12)
    cipher = aesgcm_new(bytearray(KEY))
    # seal() retorna ciphertext || tag (tag nos últimos 16 bytes)
    result = cipher.seal(bytearray(iv), bytearray(plaintext.encode()))
    tag    = bytes(result[-16:])
    enc    = bytes(result[:-16])
    return f"{base64.b64encode(iv).decode()}::{tag.hex()}::{enc.hex()}"


def decrypt(encrypted: str) -> bytes:
    iv_b64, tag_hex, ct_hex = encrypted.split("::")
    iv     = bytearray(base64.b64decode(iv_b64))
    tag    = bytes.fromhex(tag_hex)
    ct     = bytes.fromhex(ct_hex)
    cipher = aesgcm_new(bytearray(KEY))
    # open() espera ciphertext || tag concatenados
    result = cipher.open(iv, bytearray(ct + tag))
    if result is None:
        raise ValueError("Decryption failed: tag mismatch")
    return bytes(result)


def solve_sha2(challenge_input: str, checksum: str, difficulty: int) -> str:
    base  = (challenge_input + checksum).encode()
    bits  = difficulty // 4 + 1          # hex chars a verificar
    shift = bits * 4 - difficulty        # right-shift para testar zeros iniciais
    nonce = 0
    while True:
        h = hashlib.sha256(base + str(nonce).encode()).hexdigest()
        if int(h[:bits], 16) >> shift == 0:
            return str(nonce)
        nonce += 1