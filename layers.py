# -*- coding: utf-8 -*-
import hmac
import hashlib
import struct

from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM, ChaCha20Poly1305, AESCCM, AESGCMSIV,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag

from Crypto.Cipher import AES as PC_AES
from Crypto.Cipher import Salsa20 as PC_Salsa20

import nacl.bindings as nb


class LayerError(Exception):
    pass


def _hmac_tag(mac_key: bytes, nonce: bytes, ciphertext: bytes, digest) -> bytes:
    h = hmac.new(mac_key, digestmod=digest)
    h.update(nonce)
    h.update(ciphertext)
    return h.digest()


def _hmac_verify(mac_key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, digest) -> None:
    expected = _hmac_tag(mac_key, nonce, ciphertext, digest)
    if not hmac.compare_digest(expected, tag):
        raise LayerError("HMAC verification failed (wrong password or corrupted data)")


def l1_encrypt(key, nonce, pt):
    aead = AESGCM(key)
    out = aead.encrypt(nonce, pt, None)
    return out[:-16], out[-16:]

def l1_decrypt(key, nonce, ct, tag):
    aead = AESGCM(key)
    try:
        return aead.decrypt(nonce, ct + tag, None)
    except InvalidTag:
        raise LayerError("AES-256-GCM verification failed")


def l2_encrypt(key, nonce, pt):
    aead = ChaCha20Poly1305(key)
    out = aead.encrypt(nonce, pt, None)
    return out[:-16], out[-16:]

def l2_decrypt(key, nonce, ct, tag):
    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(nonce, ct + tag, None)
    except InvalidTag:
        raise LayerError("ChaCha20-Poly1305 verification failed")


def l3_encrypt(key, nonce, pt):
    c = PC_AES.new(key, PC_AES.MODE_EAX, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt)
    return ct, tag

def l3_decrypt(key, nonce, ct, tag):
    c = PC_AES.new(key, PC_AES.MODE_EAX, nonce=nonce)
    try:
        return c.decrypt_and_verify(ct, tag)
    except ValueError:
        raise LayerError("AES-256-EAX verification failed")


def l4_encrypt(key, nonce, pt):
    c = PC_AES.new(key, PC_AES.MODE_OCB, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt)
    return ct, tag

def l4_decrypt(key, nonce, ct, tag):
    c = PC_AES.new(key, PC_AES.MODE_OCB, nonce=nonce)
    try:
        return c.decrypt_and_verify(ct, tag)
    except ValueError:
        raise LayerError("AES-256-OCB verification failed")


def l5_encrypt(key, nonce, pt):
    c = PC_AES.new(key, PC_AES.MODE_SIV, nonce=nonce)
    ct, tag = c.encrypt_and_digest(pt)
    return ct, tag

def l5_decrypt(key, nonce, ct, tag):
    c = PC_AES.new(key, PC_AES.MODE_SIV, nonce=nonce)
    try:
        return c.decrypt_and_verify(ct, tag)
    except ValueError:
        raise LayerError("AES-256-SIV verification failed")


def l6_encrypt(key, nonce, pt):
    aead = AESCCM(key, tag_length=16)
    out = aead.encrypt(nonce, pt, None)
    return out[:-16], out[-16:]

def l6_decrypt(key, nonce, ct, tag):
    aead = AESCCM(key, tag_length=16)
    try:
        return aead.decrypt(nonce, ct + tag, None)
    except InvalidTag:
        raise LayerError("AES-256-CCM verification failed")


def l7_encrypt(key, nonce, pt):
    ct_and_tag = nb.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, None, nonce, key)
    return ct_and_tag[:-16], ct_and_tag[-16:]

def l7_decrypt(key, nonce, ct, tag):
    try:
        return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ct + tag, None, nonce, key)
    except Exception:
        raise LayerError("XChaCha20-Poly1305 verification failed")


def l8_encrypt(key, nonce, pt):
    enc_key, mac_key = key[:32], key[32:64]
    c = PC_Salsa20.new(key=enc_key, nonce=nonce)
    ct = c.encrypt(pt)
    tag = _hmac_tag(mac_key, nonce, ct, hashlib.sha256)
    return ct, tag

def l8_decrypt(key, nonce, ct, tag):
    enc_key, mac_key = key[:32], key[32:64]
    _hmac_verify(mac_key, nonce, ct, tag, hashlib.sha256)
    c = PC_Salsa20.new(key=enc_key, nonce=nonce)
    return c.decrypt(ct)


def l9_encrypt(key, nonce, pt):
    aead = AESGCMSIV(key)
    out = aead.encrypt(nonce, pt, None)
    return out[:-16], out[-16:]

def l9_decrypt(key, nonce, ct, tag):
    aead = AESGCMSIV(key)
    try:
        return aead.decrypt(nonce, ct + tag, None)
    except InvalidTag:
        raise LayerError("AES-256-GCM-SIV verification failed")


def l10_encrypt(key, nonce, pt):
    aead = AESGCM(key)
    out = aead.encrypt(nonce, pt, None)
    return out[:-16], out[-16:]

def l10_decrypt(key, nonce, ct, tag):
    aead = AESGCM(key)
    try:
        return aead.decrypt(nonce, ct + tag, None)
    except InvalidTag:
        raise LayerError("AES-192-GCM verification failed")


def _chacha20_split_nonce(derived_nonce_16: bytes):
    nonce_12   = derived_nonce_16[:12]
    counter_le = struct.pack("<I", struct.unpack(">I", derived_nonce_16[12:])[0])
    return counter_le + nonce_12


def l11_encrypt(key, nonce, pt):
    enc_key, mac_key = key[:32], key[32:96]
    chacha_nonce = _chacha20_split_nonce(nonce)
    enc = Cipher(algorithms.ChaCha20(enc_key, chacha_nonce), mode=None).encryptor()
    ct = enc.update(pt) + enc.finalize()
    tag = _hmac_tag(mac_key, nonce, ct, hashlib.sha512)
    return ct, tag

def l11_decrypt(key, nonce, ct, tag):
    enc_key, mac_key = key[:32], key[32:96]
    _hmac_verify(mac_key, nonce, ct, tag, hashlib.sha512)
    chacha_nonce = _chacha20_split_nonce(nonce)
    dec = Cipher(algorithms.ChaCha20(enc_key, chacha_nonce), mode=None).decryptor()
    return dec.update(ct) + dec.finalize()


def l12_encrypt(key, nonce, pt):
    enc_key, mac_key = key[:32], key[32:64]
    enc = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    tag = _hmac_tag(mac_key, nonce, ct, hashlib.sha256)
    return ct, tag

def l12_decrypt(key, nonce, ct, tag):
    enc_key, mac_key = key[:32], key[32:64]
    _hmac_verify(mac_key, nonce, ct, tag, hashlib.sha256)
    dec = Cipher(algorithms.AES(enc_key), modes.CTR(nonce)).decryptor()
    return dec.update(ct) + dec.finalize()


def l13_encrypt(key, nonce, pt):
    xts_key, mac_key = key[:64], key[64:96]
    enc = Cipher(algorithms.AES(xts_key), modes.XTS(nonce)).encryptor()
    ct = enc.update(pt) + enc.finalize()
    tag = _hmac_tag(mac_key, nonce, ct, hashlib.sha256)
    return ct, tag

def l13_decrypt(key, nonce, ct, tag):
    xts_key, mac_key = key[:64], key[64:96]
    _hmac_verify(mac_key, nonce, ct, tag, hashlib.sha256)
    dec = Cipher(algorithms.AES(xts_key), modes.XTS(nonce)).decryptor()
    return dec.update(ct) + dec.finalize()


def l14_encrypt(key, nonce, pt):
    aead = AESGCM(key)
    out = aead.encrypt(nonce, pt, None)
    return out[:-16], out[-16:]

def l14_decrypt(key, nonce, ct, tag):
    aead = AESGCM(key)
    try:
        return aead.decrypt(nonce, ct + tag, None)
    except InvalidTag:
        raise LayerError("AES-256-GCM (final seal) verification failed")


LAYERS = [
    {"id": 1,  "name": "AES-256-GCM",                "key_len": 32, "nonce_len": 12, "tag_len": 16, "enc": l1_encrypt,  "dec": l1_decrypt},
    {"id": 2,  "name": "ChaCha20-Poly1305",           "key_len": 32, "nonce_len": 12, "tag_len": 16, "enc": l2_encrypt,  "dec": l2_decrypt},
    {"id": 3,  "name": "AES-256-EAX",                 "key_len": 32, "nonce_len": 16, "tag_len": 16, "enc": l3_encrypt,  "dec": l3_decrypt},
    {"id": 4,  "name": "AES-256-OCB",                 "key_len": 32, "nonce_len": 15, "tag_len": 16, "enc": l4_encrypt,  "dec": l4_decrypt},
    {"id": 5,  "name": "AES-256-SIV",                 "key_len": 64, "nonce_len": 16, "tag_len": 16, "enc": l5_encrypt,  "dec": l5_decrypt},
    {"id": 6,  "name": "AES-256-CCM",                 "key_len": 32, "nonce_len": 11, "tag_len": 16, "enc": l6_encrypt,  "dec": l6_decrypt},
    {"id": 7,  "name": "XChaCha20-Poly1305",          "key_len": 32, "nonce_len": 24, "tag_len": 16, "enc": l7_encrypt,  "dec": l7_decrypt},
    {"id": 8,  "name": "Salsa20 + HMAC-SHA256",       "key_len": 64, "nonce_len": 8,  "tag_len": 32, "enc": l8_encrypt,  "dec": l8_decrypt},
    {"id": 9,  "name": "AES-256-GCM-SIV",             "key_len": 32, "nonce_len": 12, "tag_len": 16, "enc": l9_encrypt,  "dec": l9_decrypt},
    {"id": 10, "name": "AES-192-GCM",                 "key_len": 24, "nonce_len": 12, "tag_len": 16, "enc": l10_encrypt, "dec": l10_decrypt},
    {"id": 11, "name": "ChaCha20 + HMAC-SHA512",      "key_len": 96, "nonce_len": 16, "tag_len": 64, "enc": l11_encrypt, "dec": l11_decrypt},
    {"id": 12, "name": "AES-256-CTR + HMAC-SHA256",   "key_len": 64, "nonce_len": 16, "tag_len": 32, "enc": l12_encrypt, "dec": l12_decrypt},
    {"id": 13, "name": "AES-256-XTS + HMAC-SHA256",   "key_len": 96, "nonce_len": 16, "tag_len": 32, "enc": l13_encrypt, "dec": l13_decrypt},
    {"id": 14, "name": "AES-256-GCM (final seal)",    "key_len": 32, "nonce_len": 12, "tag_len": 16, "enc": l14_encrypt, "dec": l14_decrypt},
]

assert len(LAYERS) == 14
