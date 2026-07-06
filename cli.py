# -*- coding: utf-8 -*-
import argparse
import getpass
import gc
import hmac
import os
import sys
import time

import engine
import kdf
from layers import LAYERS

BANNER = r"""
======================================================
      14-LAYER FILE ENCRYPTION TOOL (CVLT14)
======================================================
"""

DANGEROUS_EXTS = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".sh", ".msi", ".scr", ".pif"}


def _str_eq_constant_time(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _ask_passwords_for_encryption():
    passwords = []
    seen_raw = []

    for i in range(1, 15):
        while True:
            p1 = getpass.getpass(f"Password {i:2}/14: ")

            if len(p1) < 8:
                print("  Password too short, minimum 8 characters.\n")
                p1 = ""
                continue

            is_dup = any(_str_eq_constant_time(p1, prev) for prev in seen_raw)
            if is_dup:
                print(
                    "  ERROR: This password was already used for a previous layer.\n"
                    "  Each layer MUST have a unique password. Please choose a different one.\n"
                )
                p1 = ""
                continue

            p2 = getpass.getpass(f"Password {i:2}/14 (confirm)           : ")
            if p1 != p2:
                print("  Passwords do not match, try again.\n")
                p1 = p2 = ""
                continue

            pw_bytes = bytearray(p1.encode("utf-8"))
            seen_raw.append(p1)
            del p1, p2
            break

        passwords.append(pw_bytes)

    seen_raw.clear()
    del seen_raw
    gc.collect()

    return passwords


def _ask_passwords_for_decryption():
    passwords = []
    for i in range(1, 15):
        p = getpass.getpass(f"Password {i:2}/14: ")
        pw_bytes = bytearray(p.encode("utf-8"))
        del p
        passwords.append(pw_bytes)
    return passwords


def _wipe_passwords(passwords):
    for pw in passwords:
        kdf.secure_zero(pw)
    passwords.clear()


def _progress_printer(prefix):
    def _cb(step, total, name):
        bar_len = 30
        filled = int(bar_len * step / total)
        bar = "#" * filled + "-" * (bar_len - filled)
        print(f"\r{prefix} [{bar}] {step}/{total}   ", end="", flush=True)
        if step == total:
            print()
    return _cb


def cmd_encrypt(args):
    if not os.path.isfile(args.input):
        print(f"ERROR: '{args.input}' not found.")
        sys.exit(1)

    output = args.output or (args.input + ".cv14")

    if os.path.exists(output) and not args.yes:
        ans = input(f"'{output}' already exists. Overwrite? (y/N): ")
        if ans.strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            sys.exit(0)

    passwords = _ask_passwords_for_encryption()

    print("\nEncrypting...\n")

    t0 = time.time()
    try:
        engine.encrypt_file(args.input, output, passwords, progress_cb=_progress_printer("Encrypting"))
    except engine.EncryptionError as e:
        print(f"\nERROR: {e}")
        sys.exit(1)
    finally:
        _wipe_passwords(passwords)
        del passwords
        gc.collect()

    t1 = time.time()

    print(f"\n Done. Output file: {output}")
    print(f"  Time: {t1 - t0:.1f}s, Size: {os.path.getsize(output):,} bytes")

def cmd_decrypt(args):
    if not os.path.isfile(args.input):
        print(f"ERROR: '{args.input}' not found.")
        sys.exit(1)

    passwords = _ask_passwords_for_decryption()

    print("\nDecrypting...\n")

    tmp_output = args.output or (args.input + ".decrypting.tmp")

    t0 = time.time()
    try:
        original_filename = engine.decrypt_file(
            args.input, tmp_output, passwords, progress_cb=_progress_printer("Decrypting")
        )
    except engine.DecryptionError as e:
        print(f"\n {e}")
        if os.path.exists(tmp_output):
            try:
                os.remove(tmp_output)
            except OSError as rm_err:
                print(f"  WARNING: Could not delete temp file '{tmp_output}': {rm_err}")
        sys.exit(1)
    finally:
        _wipe_passwords(passwords)
        del passwords
        gc.collect()

    t1 = time.time()

    ext = os.path.splitext(original_filename)[1].lower()
    if ext in DANGEROUS_EXTS:
        print(f"\n[WARNING] The extracted file '{original_filename}' is an EXECUTABLE.")
        ans = input("Are you sure you want to save it? (y/N): ")
        if ans.strip().lower() not in ("y", "yes"):
            print("Cancelled. File deleted.")
            try:
                os.remove(tmp_output)
            except OSError as rm_err:
                print(f"  WARNING: Could not delete temp file '{tmp_output}': {rm_err}")
            sys.exit(0)

    if args.output:
        final_path = args.output
    else:
        final_dir = os.path.dirname(os.path.abspath(args.input))
        final_path = os.path.join(final_dir, original_filename)
        if os.path.abspath(final_path) != os.path.abspath(tmp_output):
            if os.path.exists(final_path) and not args.yes:
                ans = input(f"'{final_path}' already exists. Overwrite? (y/N): ")
                if ans.strip().lower() not in ("y", "yes"):
                    final_path = tmp_output
                else:
                    os.replace(tmp_output, final_path)
            else:
                os.replace(tmp_output, final_path)

    print(f"\n Done. Original filename: {original_filename}")
    print(f"  Saved to: {final_path}")
    print(f"  Time: {t1 - t0:.1f}s")


def _prompt_file(prompt):
    path = input(prompt).strip().strip('"').strip("'")
    return path


def interactive_menu():
    print(BANNER)
    while True:
        print("  [1] Encrypt a file")
        print("  [2] Decrypt a file")
        print("  [0] Exit")
        print()
        choice = input("  Select: ").strip()

        if choice == "0":
            print("\nBye.")
            break

        elif choice == "1":
            print()
            file_path = _prompt_file("  File to encrypt: ")
            if not os.path.isfile(file_path):
                print(f"\n  ERROR: '{file_path}' not found.\n")
                continue

            output = file_path + ".cv14"
            if os.path.exists(output):
                ans = input(f"\n  '{output}' already exists. Overwrite? (y/N): ")
                if ans.strip().lower() not in ("y", "yes"):
                    print("  Cancelled.\n")
                    continue

            passwords = _ask_passwords_for_encryption()
            print("\nEncrypting...\n")
            t0 = time.time()
            try:
                engine.encrypt_file(file_path, output, passwords,
                                     progress_cb=_progress_printer("Encrypting"))
            except engine.EncryptionError as e:
                print(f"\n  ERROR: {e}\n")
                continue
            finally:
                _wipe_passwords(passwords)
                del passwords
                gc.collect()
            t1 = time.time()
            print(f"\n Done. Output: {output}")
            print(f"  Time: {t1 - t0:.1f}s  |  Size: {os.path.getsize(output):,} bytes")

        elif choice == "2":
            print()
            file_path = _prompt_file("  File to decrypt (.cv14): ")
            if not os.path.isfile(file_path):
                print(f"\n  ERROR: '{file_path}' not found.\n")
                continue

            passwords = _ask_passwords_for_decryption()
            tmp_output = file_path + ".decrypting.tmp"
            print("\nDecrypting...\n")
            t0 = time.time()
            try:
                original_filename = engine.decrypt_file(
                    file_path, tmp_output, passwords,
                    progress_cb=_progress_printer("Decrypting")
                )
            except engine.DecryptionError as e:
                print(f"\n {e}\n")
                if os.path.exists(tmp_output):
                    try:
                        os.remove(tmp_output)
                    except OSError as rm_err:
                        print(f"\n  WARNING: Could not delete temp file '{tmp_output}': {rm_err}\n")
                continue
            finally:
                _wipe_passwords(passwords)
                del passwords
                gc.collect()
            t1 = time.time()

            ext = os.path.splitext(original_filename)[1].lower()
            if ext in DANGEROUS_EXTS:
                print(f"\n  [WARNING] The extracted file '{original_filename}' is an EXECUTABLE.")
                ans = input("  Are you sure you want to save it? (y/N): ")
                if ans.strip().lower() not in ("y", "yes"):
                    print("  Cancelled. File deleted.\n")
                    try:
                        os.remove(tmp_output)
                    except OSError as rm_err:
                        print(f"  WARNING: Could not delete temp file '{tmp_output}': {rm_err}\n")
                    continue

            final_dir = os.path.dirname(os.path.abspath(file_path))
            final_path = os.path.join(final_dir, original_filename)
            if os.path.exists(final_path):
                ans = input(f"\n  '{final_path}' already exists. Overwrite? (y/N): ")
                if ans.strip().lower() in ("y", "yes"):
                    os.replace(tmp_output, final_path)
                else:
                    final_path = tmp_output
            else:
                os.replace(tmp_output, final_path)

            print(f"\n Done. Saved to: {final_path}")
            print(f"  Time: {t1 - t0:.1f}s\n")

        else:
            print("  Invalid choice.\n")

    input("\nPress Enter to exit...")


def main():
    parser = argparse.ArgumentParser(
        description="14-Layer File Encryption Tool"
    )
    sub = parser.add_subparsers(dest="command")

    p_enc = sub.add_parser("encrypt", help="Encrypt a file with 14 layers")
    p_enc.add_argument("input", help="File to encrypt")
    p_enc.add_argument("-o", "--output", help="Output file (default: <file>.cv14)")
    p_enc.add_argument("-y", "--yes", action="store_true", help="Skip overwrite confirmation")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Decrypt a .cv14 encrypted file")
    p_dec.add_argument("input", help=".cv14 file to decrypt")
    p_dec.add_argument("-o", "--output", help="Output file (default: original filename)")
    p_dec.add_argument("-y", "--yes", action="store_true", help="Skip overwrite confirmation")
    p_dec.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()

    if args.command is None:
        interactive_menu()
        return

    print(BANNER)
    args.func(args)


if __name__ == "__main__":
    main()
