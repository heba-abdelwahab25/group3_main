"""
Advanced PQC Client with JSON payload support and extended features.
Use this version if you need to send additional metadata along with the public key.
"""
import socket
import json
import sys
import time
from pqcrypto.kem.kyber512 import generate_keypair, encrypt, decrypt

# ===== Configuration =====
HOST = '127.0.0.1'  # server IP
PORT = 65432        # server port
BUFFER_SIZE = 4096  # buffer size for receiving data
TIMEOUT = 10        # connection timeout in seconds
USE_JSON = False    # Set to True to send JSON-encoded payloads

def send_json_payload(sock, data):
    """Send JSON-encoded payload with length prefix."""
    payload = json.dumps(data).encode('utf-8')
    length = len(payload).to_bytes(4, byteorder='big')
    sock.sendall(length + payload)
    return len(payload)

def receive_json_payload(sock):
    """Receive JSON-encoded payload with length prefix."""
    length_bytes = sock.recv(4)
    if len(length_bytes) != 4:
        raise ValueError("Failed to receive length prefix")
    length = int.from_bytes(length_bytes, byteorder='big')
    data = b''
    while len(data) < length:
        chunk = sock.recv(min(length - len(data), BUFFER_SIZE))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        data += chunk
    return json.loads(data.decode('utf-8'))

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
                if USE_JSON:
                    # Send JSON payload with public key and metadata
                    print("[*] Sending JSON payload with public key to server...")
                    payload = {
                        'client_id': 1,
                        'timestamp': time.time(),
                        'pub_key': public_key.hex(),
                        'algorithm': 'kyber512'
                    }
                    send_json_payload(s, payload)
                    print(f"[+] JSON payload sent.")
                    
                    # Receive JSON response
                    print("[*] Waiting for JSON response from server...")
                    response = receive_json_payload(s)
                    print(f"[+] Response received: {response}")
                    
                    # Extract ciphertext from response
                    if 'ciphertext' in response:
                        ciphertext = bytes.fromhex(response['ciphertext'])
                    else:
                        print("[!] Error: No ciphertext in server response")
                        sys.exit(1)
                else:
                    # 3️⃣ Send public key to server (raw bytes)
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
                    
                    # The shared secret can now be used for symmetric encryption (AES, etc.)
                    print("\n[+] Key exchange complete! Shared secret ready for use.")
                    
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

