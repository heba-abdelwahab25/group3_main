import socket
import json
import sys
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

# ===== Configuration =====
HOST = '127.0.0.1'  # server IP
PORT = 65432        # server port
BUFFER_SIZE = 2048  # buffer size for receiving data
TIMEOUT = 10        # connection timeout in seconds

def main():
    try:
        # 1️⃣ Generate PQC keypair
        print("[*] Generating Kyber keypair...")
        public_key, secret_key = generate_keypair()
        print(f"[+] Keypair generated. Public key size: {len(public_key)} bytes")

        # 2️⃣ Connect to server
        print(f"[*] Connecting to server {HOST}:{PORT}...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            try:
                s.connect((HOST, PORT))
                print("[+] Connected to server.")
            except socket.timeout:
                print(f"[!] Error: Connection timeout after {TIMEOUT} seconds")
                sys.exit(1)
            except ConnectionRefusedError:
                print(f"[!] Error: Connection refused. Is the server running on {HOST}:{PORT}?")
                sys.exit(1)
            except Exception as e:
                print(f"[!] Error connecting to server: {e}")
                sys.exit(1)

            try:
                # 3️⃣ Send public key to server
                print("[*] Sending public key to server...")
                s.sendall(public_key)
                print(f"[+] Public key sent ({len(public_key)} bytes).")

                # 4️⃣ Receive ciphertext from server
                print("[*] Waiting for ciphertext from server...")
                ciphertext = s.recv(BUFFER_SIZE)
                
                if not ciphertext:
                    print("[!] Error: No data received from server")
                    sys.exit(1)
                
                print(f"[+] Ciphertext received ({len(ciphertext)} bytes).")

                # 5️⃣ Decapsulate to get shared secret
                print("[*] Decapsulating ciphertext to get shared secret...")
                try:
                    shared_secret = decrypt(ciphertext, secret_key)
                    print("[+] Shared secret established successfully!")
                    print(f"[+] Shared secret (hex): {shared_secret.hex()}")
                    print(f"[+] Shared secret length: {len(shared_secret)} bytes")
                    
                    # Optional: Display first few bytes for verification
                    print(f"[+] First 16 bytes: {shared_secret[:16].hex()}")
                    
                except Exception as e:
                    print(f"[!] Error during decapsulation: {e}")
                    sys.exit(1)

            except socket.timeout:
                print("[!] Error: Timeout while communicating with server")
                sys.exit(1)
            except Exception as e:
                print(f"[!] Error during communication: {e}")
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

