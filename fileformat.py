# -*- coding: utf-8 -*-
import struct
import os
import gc

MAGIC = b"CVLT14"
VERSION = (2, 2)
CHUNK_COUNT_SIZE = 8
CHUNK_MAC_SIZE = 32
CHUNK_COUNT_PLACEHOLDER = b"\x00" * (CHUNK_COUNT_SIZE + CHUNK_MAC_SIZE)


class FormatError(Exception):
    pass


def _pack_lp(data: bytes) -> bytes:
    if len(data) > 255:
        raise FormatError("Field exceeds 255 bytes")
    return bytes([len(data)]) + data


def _unpack_lp(buf: bytes, offset: int):
    if offset >= len(buf):
        raise FormatError("Unexpected end of header")
    length = buf[offset]
    offset += 1
    if offset + length > len(buf):
        raise FormatError("Unexpected end of header data")
    val = buf[offset: offset + length]
    offset += length
    return val, offset


def pack_layer_meta(layer_id: int, salt: bytes, nonce: bytes) -> bytes:
    out = bytes([layer_id])
    out += _pack_lp(salt)
    out += _pack_lp(nonce)
    return out


def unpack_layer_meta(buf: bytes, offset: int):
    if offset >= len(buf):
        raise FormatError("Unexpected end of header")
    layer_id = buf[offset]
    offset += 1
    salt, offset = _unpack_lp(buf, offset)
    nonce, offset = _unpack_lp(buf, offset)
    return {"layer_id": layer_id, "salt": salt, "nonce": nonce}, offset


def pack_header(layer_metas: list) -> bytes:
    if len(layer_metas) != 14:
        raise FormatError("Exactly 14 layer metadata entries required")
    out = bytearray()
    out += MAGIC
    out += bytes(VERSION)
    for (layer_id, salt, nonce) in layer_metas:
        out += pack_layer_meta(layer_id, salt, nonce)
    out += CHUNK_COUNT_PLACEHOLDER
    return bytes(out)


def chunk_count_offset(layer_metas_bytes_len: int) -> int:
    return 6 + 2 + layer_metas_bytes_len


def write_chunk_count(f, offset: int, count: int, mac: bytes) -> None:
    f.seek(offset)
    f.write(struct.pack(">Q", count))
    f.write(mac)
    f.seek(0, 2)


def parse_header(f) -> dict:
    magic = f.read(6)
    if magic != MAGIC:
        raise FormatError("Invalid file: CVLT14 signature not found (wrong file or corrupted)")

    ver = f.read(2)
    if len(ver) < 2:
        raise FormatError("File too short")
    version = (ver[0], ver[1])

    if version == (2, 0):
        raise FormatError(
            "File format version 2.0 is no longer supported. "
            "This file was created by an older, vulnerable version of CVLT14 "
            "and cannot be safely decrypted. Re-encrypt the original data "
            "with the current version to obtain a v2.1 file."
        )
    if version != VERSION:
        raise FormatError(
            f"Unsupported file format version {version[0]}.{version[1]} "
            f"(this tool supports version {VERSION[0]}.{VERSION[1]}). "
            "The file may have been created by a different/newer version of this tool."
        )

    header_peek = f.read(2048)

    offset = 0
    layer_metas = []
    for _ in range(14):
        meta, offset = unpack_layer_meta(header_peek, offset)
        layer_metas.append(meta)

    if offset + CHUNK_COUNT_SIZE > len(header_peek):
        raise FormatError("Header too short: chunk-count field missing")
    chunk_count = struct.unpack(">Q", header_peek[offset: offset + CHUNK_COUNT_SIZE])[0]
    offset += CHUNK_COUNT_SIZE

    chunk_mac = None
    if version >= (2, 2):
        if offset + CHUNK_MAC_SIZE > len(header_peek):
            raise FormatError("Header too short: chunk-count MAC missing")
        chunk_mac = header_peek[offset: offset + CHUNK_MAC_SIZE]
        offset += CHUNK_MAC_SIZE

    if chunk_count == 0:
        raise FormatError("Chunk count is zero — the file is empty or was not properly finalised during encryption (corrupted file).")

    total_header_read = 8 + offset
    f.seek(total_header_read)

    return {"version": version, "layers": layer_metas, "chunk_count": chunk_count, "chunk_mac": chunk_mac}
