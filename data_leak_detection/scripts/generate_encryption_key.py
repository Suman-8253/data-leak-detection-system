"""
Generate a new AES-256 encryption key (base64-encoded).
Run this script ONCE and save the output to your .env file.
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.encryption import generate_key

if __name__ == '__main__':
    key = generate_key()
    print("=" * 60)
    print("  AES-256 ENCRYPTION KEY (Base64-encoded)")
    print("=" * 60)
    print(f"\n  {key}\n")
    print("  Add this to your .env file as:")
    print(f"  ENCRYPTION_KEY={key}")
    print()
    print("  WARNING: Do NOT lose this key!")
    print("  Existing encrypted records cannot be recovered without it.")
    print("=" * 60)
