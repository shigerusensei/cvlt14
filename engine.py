# -*- coding: utf-8 -*-
import os
import struct
import gc
import hmac
import hashlib
from typing import List, Callable, Optional

import kdf
from layers import LAYERS, LayerError
import fileformat


class DecryptionError(Exception):
    pass


class EncryptionError(Exception):
    pass


_PAD_BLOCK = 16
CHUNK_SIZE = 65536


def _pkcs7_pad(data: bytes) -> bytes:
    pad_len = _PAD_BLOCK - (len(data) % _PAD_BLOCK)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    if len(data) == 0:
        raise DecryptionError("Decryption failed (invalid padding)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > _PAD_BLOCK or pad_len > len(data):
        raise DecryptionError("Decryption failed (invalid padding)")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise DecryptionError("Decryption failed (invalid padding)")
    return data[:-pad_len]


def _derive_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    total_bits = len(base_nonce) * 8
    reserved_bits = min(32, total_bits // 2)
    base_int = int.from_bytes(base_nonce, 'big')
    modulus = 1 << total_bits
    value = (base_int + (chunk_index << reserved_bits)) % modulus
    return value.to_bytes(len(base_nonce), 'big')


def _wipe_keys(keys: list) -> None:
    for k in keys:
        if isinstance(k, bytearray):
            kdf.secure_zero(k)
        elif isinstance(k, (bytes, memoryview)):
            pass
    keys.clear()
    gc.collect()


def stream_plaintext(input_path: str, chunk_size: int):
    filename = os.path.basename(input_path).encode("utf-8")
    if len(filename) > 1024:
        raise EncryptionError("Filename too long (max 1024 bytes)")
    header = struct.pack(">H", len(filename)) + filename

    with open(input_path, "rb") as f:
        buf = bytearray(header)
        while True:
            while len(buf) < chunk_size:
                data = f.read(chunk_size - len(buf))
                if not data:
                    break
                buf.extend(data)

            if len(buf) < chunk_size:
                yield bytes(buf), True
                break
            else:
                yield bytes(buf), False
                buf.clear()


def encrypt_file(
    input_path: str,
    output_path: str,
    passwords: List[bytes],
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> None:
    if len(passwords) != 14:
        raise EncryptionError(f"Exactly 14 passwords required, got {len(passwords)}")

    layer_metas = []
    keys = []

    try:
        for i, layer in enumerate(LAYERS):
            salt = kdf.generate_salt()
            base_nonce = os.urandom(layer["nonce_len"])
            key = kdf.derive_key(passwords[i], salt, layer["key_len"])
            keys.append(bytearray(key))
            layer_metas.append((layer["id"], salt, base_nonce))
            if progress_cb:
                progress_cb(i + 1, 14, "Deriving keys: " + layer["name"])

        header_bytes = fileformat.pack_header(layer_metas)
        layer_meta_bytes_len = len(header_bytes) - 6 - 2 - len(fileformat.CHUNK_COUNT_PLACEHOLDER)
        cc_offset = fileformat.chunk_count_offset(layer_meta_bytes_len)

        try:
            with open(output_path, "wb") as f_out:
                f_out.write(header_bytes)

                chunk_index = 0
                for pt_chunk, is_last in stream_plaintext(input_path, CHUNK_SIZE):
                    if is_last:
                        pt_chunk = _pkcs7_pad(pt_chunk)

                    data = pt_chunk
                    for i, layer in enumerate(LAYERS):
                        key = bytes(keys[i])
                        base_nonce = layer_metas[i][2]
                        chunk_nonce = _derive_chunk_nonce(base_nonce, chunk_index)
                        ct, tag = layer["enc"](key, chunk_nonce, data)
                        data = ct + tag

                    f_out.write(data)
                    chunk_index += 1

                if chunk_index == 0:
                    raise EncryptionError("Input file produced zero chunks (empty or unreadable)")
                
                # V2.2: Compute HMAC of the chunk_count using Layer 1's key (keys[0])
                cc_mac = hmac.new(bytes(keys[0]), struct.pack(">Q", chunk_index), hashlib.sha256).digest()
                fileformat.write_chunk_count(f_out, cc_offset, chunk_index, cc_mac)
        except BaseException:
            # Hata durumunda yarım yazılan çıktı dosyasını temizle
            try:
                if os.path.exists(output_path):
                    os.remove(output_path)
            except OSError:
                pass
            raise

    finally:
        _wipe_keys(keys)


def decrypt_file(
    input_path: str,
    output_path: str,
    passwords: List[bytes],
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> str:
    if len(passwords) != 14:
        raise DecryptionError(f"Exactly 14 passwords required, got {len(passwords)}")

    keys = []

    try:
        with open(input_path, "rb") as f_in:
            try:
                parsed = fileformat.parse_header(f_in)
            except fileformat.FormatError as e:
                raise DecryptionError(f"Invalid file format: {e}")

            layer_metas = parsed["layers"]
            expected_chunk_count = parsed["chunk_count"]

            reversed_layers = list(zip(LAYERS, layer_metas, passwords))[::-1]

            for step, (layer, meta, password) in enumerate(reversed_layers):
                if meta["layer_id"] != layer["id"]:
                    raise DecryptionError(
                        "Invalid file format: unexpected layer ID in header "
                        "(file is corrupted or not a valid CVLT14 file)"
                    )
                key = kdf.derive_key(password, meta["salt"], layer["key_len"])
                keys.append(bytearray(key))
                if progress_cb:
                    progress_cb(step + 1, 14, "Deriving keys: " + layer["name"])
            
            if parsed["version"] >= (2, 2):
                chunk_mac = parsed.get("chunk_mac")
                if not chunk_mac:
                    raise DecryptionError("Decryption failed: chunk count MAC missing in v2.2+ file")
                
                # keys listesi ters (reversed_layers) sırayla oluşturulduğu için, Layer 1'in anahtarı keys[-1]'dedir.
                expected_mac = hmac.new(bytes(keys[-1]), struct.pack(">Q", expected_chunk_count), hashlib.sha256).digest()
                if not hmac.compare_digest(expected_mac, chunk_mac):
                    raise DecryptionError(
                        "Decryption failed: chunk count signature mismatch. "
                        "The file has been tampered with or truncated."
                    )

            chunk_overhead = sum(layer["tag_len"] for layer in LAYERS)
            enc_chunk_size = CHUNK_SIZE + chunk_overhead

            chunk_index = 0
            first_chunk = True
            filename = ""

            with open(output_path, "wb") as f_out:
                prev_pt = None

                while True:
                    enc_chunk = f_in.read(enc_chunk_size)
                    if not enc_chunk:
                        break

                    if chunk_index >= expected_chunk_count:
                        raise DecryptionError(
                            "Decryption failed: file contains more chunks than "
                            "declared in the header (file is corrupted or tampered)."
                        )

                    data = enc_chunk

                    for step, (layer, meta, _) in enumerate(reversed_layers):
                        key = bytes(keys[step])
                        base_nonce = meta["nonce"]
                        chunk_nonce = _derive_chunk_nonce(base_nonce, chunk_index)
                        tag_len = layer["tag_len"]

                        if len(data) < tag_len:
                            raise DecryptionError(
                                "Decryption failed: chunk is too short to contain "
                                "the expected authentication tag (file is corrupted)."
                            )

                        ct, tag = data[:-tag_len], data[-tag_len:]
                        try:
                            data = layer["dec"](key, chunk_nonce, ct, tag)
                        except Exception:
                            raise DecryptionError(
                                "Decryption failed: wrong password or corrupted chunk."
                            )

                    if first_chunk:
                        if len(data) < 2:
                            raise DecryptionError("Corrupted file (header too short)")
                        name_len = struct.unpack(">H", data[:2])[0]
                        if name_len > 1024:
                            raise DecryptionError(
                                f"Corrupted file (embedded filename length {name_len} "
                                "exceeds the 1024-byte maximum)"
                            )
                        offset = 2 + name_len
                        if len(data) < offset:
                            raise DecryptionError(
                                "Corrupted file (filename length field points past "
                                "end of first chunk)"
                            )
                        filename = data[2:offset].decode("utf-8", errors="replace")
                        safe_name = os.path.basename(filename)
                        if safe_name in ("", ".", ".."):
                            safe_name = "decrypted_output"
                        filename = safe_name
                        data = data[offset:]
                        first_chunk = False

                    if prev_pt is not None:
                        f_out.write(prev_pt)

                    prev_pt = data
                    chunk_index += 1

                if chunk_index != expected_chunk_count:
                    raise DecryptionError(
                        f"Decryption failed: expected {expected_chunk_count} chunk(s) "
                        f"but found {chunk_index}. The file has been truncated or tampered with."
                    )

                if prev_pt is not None:
                    unpadded = _pkcs7_unpad(prev_pt)
                    f_out.write(unpadded)

    finally:
        _wipe_keys(keys)

    return os.path.basename(filename)
