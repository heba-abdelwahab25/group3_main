#!/usr/bin/env python3
"""Test PQC availability"""
try:
    from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt
    print("✓ pqcrypto (pqcrypto.kem.kyber512) is available")
    PQC_AVAILABLE = True
except ImportError as e:
    print(f"✗ pqcrypto not available: {e}")
    PQC_AVAILABLE = False

if PQC_AVAILABLE:
    try:
        pub, sec = generate_keypair()
        print(f"✓ Kyber512 keypair generation works (pub: {len(pub)} bytes, sec: {len(sec)} bytes)")
    except Exception as e:
        print(f"✗ Kyber512 keypair generation failed: {e}")

