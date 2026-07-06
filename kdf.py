# -*- coding: utf-8 -*-
import ctypes
import gc
import os
from argon2.low_level import hash_secret_raw, Type

ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
SALT_LEN = 16


def generate_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(password: bytes, salt: bytes, length: int) -> bytes:
    if not isinstance(password, (bytes, bytearray)):
        raise TypeError("password must be bytes or bytearray")
    if len(salt) < 8:
        raise ValueError("salt must be at least 8 bytes")
    return hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=length,
        type=Type.ID,
    )


def secure_zero(buf: bytearray) -> None:
    if not isinstance(buf, bytearray):
        return
    n = len(buf)
    if n == 0:
        return
    try:
        ctypes.memset((ctypes.c_char * n).from_buffer(buf), 0, n)
    except Exception:
        pass
    buf[:] = bytearray(n)
    gc.collect()
