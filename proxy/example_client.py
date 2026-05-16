"""
Example client for testing the proxy server
"""
import socket
import json
import struct
import threading
import time
import base64

from crypto_engines import create_crypto_engine


def test_client(client_id, crypto_method="RSA", proxy_host='127.0.0.1', proxy_port=7000):
    """Test client that connects to proxy"""
    print(f"[Client {client_id}] Starting with crypto: {crypto_method}")
    
    try:
        # Create crypto engine
        crypto_engine = create_crypto_engine(crypto_method)
        client_pub_key, client_sec_key = crypto_engine.generate_keypair()
        
        # Connect to proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((proxy_host, proxy_port))
        print(f"[Client {client_id}] Connected to proxy")
        
        # Send handshake
        if crypto_method == "Kyber":
            pub_key_serialized = crypto_engine.serialize_public_key(client_pub_key)
            if isinstance(pub_key_serialized, bytes):
                pub_key_serialized = pub_key_serialized.hex()
        else:
            pub_key_serialized = crypto_engine.serialize_public_key(client_pub_key)
        
        handshake = {
            "client_id": client_id,
            "crypto": [crypto_method] if crypto_method else ["Kyber", "RSA"],
            "pub_key": pub_key_serialized
        }
        
        # Send handshake with length prefix
        message = json.dumps(handshake).encode('utf-8')
        length = struct.pack('>I', len(message))
        sock.sendall(length + message)
        print(f"[Client {client_id}] Handshake sent")
        
        # Receive handshake response
        length_bytes = b''
        while len(length_bytes) < 4:
            chunk = sock.recv(4 - len(length_bytes))
            if not chunk:
                print(f"[Client {client_id}] Connection closed")
                return
            length_bytes += chunk
        
        response_length = struct.unpack('>I', length_bytes)[0]
        response_bytes = b''
        while len(response_bytes) < response_length:
            chunk = sock.recv(min(4096, response_length - len(response_bytes)))
            if not chunk:
                break
            response_bytes += chunk
        
        response = json.loads(response_bytes.decode('utf-8'))
        print(f"[Client {client_id}] Handshake response: {response}")
        
        if response.get("status") != "ok":
            print(f"[Client {client_id}] Handshake failed")
            sock.close()
            return
        
        # Get proxy public key
        proxy_pub_key_data = response.get("proxy_pub_key")
        if crypto_method == "Kyber":
            proxy_pub_key = crypto_engine.deserialize_public_key(proxy_pub_key_data)
        else:
            proxy_pub_key = crypto_engine.deserialize_public_key(proxy_pub_key_data)
        
        # Send a test message
        test_message = {
            "client_id": client_id,
            "crypto": crypto_method,
            "type": "test",
            "payload": base64.b64encode(f"Hello from client {client_id}".encode()).decode()
        }
        
        message_data = json.dumps(test_message).encode('utf-8')
        encrypted = crypto_engine.encrypt(message_data, proxy_pub_key)
        
        # Send encrypted message
        length = struct.pack('>I', len(encrypted))
        sock.sendall(length + encrypted)
        print(f"[Client {client_id}] Test message sent")
        
        # Receive response
        length_bytes = b''
        while len(length_bytes) < 4:
            chunk = sock.recv(4 - len(length_bytes))
            if not chunk:
                print(f"[Client {client_id}] Connection closed")
                return
            length_bytes += chunk
        
        response_length = struct.unpack('>I', length_bytes)[0]
        encrypted_response = b''
        while len(encrypted_response) < response_length:
            chunk = sock.recv(min(4096, response_length - len(encrypted_response)))
            if not chunk:
                break
            encrypted_response += chunk
        
        # Decrypt response
        decrypted_response = crypto_engine.decrypt(encrypted_response, client_sec_key)
        print(f"[Client {client_id}] Received response: {decrypted_response.decode()}")
        
        sock.close()
        print(f"[Client {client_id}] Disconnected")
        
    except Exception as e:
        print(f"[Client {client_id}] Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Test with RSA
    print("=" * 50)
    print("Testing with RSA")
    print("=" * 50)
    test_client(1, crypto_method="RSA")
    
    time.sleep(1)
    
    # Test with multiple clients
    print("\n" + "=" * 50)
    print("Testing multiple concurrent clients")
    print("=" * 50)
    
    threads = []
    for i in range(2, 5):
        t = threading.Thread(target=test_client, args=(i, "RSA"))
        threads.append(t)
        t.start()
        time.sleep(0.5)
    
    for t in threads:
        t.join()
    
    print("\nAll clients finished")

