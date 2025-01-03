import socket
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os

# Constants
AES_KEY_SIZE = 32  # AES-256 key size in bytes
IV_SIZE = 16       # AES block size for IV
BUFFER_SIZE = 1024
LEADER_ADDRESS = ('0.0.0.0', 5000)  # Leader listens on all interfaces

# AES Encryption/Decryption Functions
def aes_encrypt(data, key, iv):
    """Encrypt data using AES-256."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def aes_decrypt(data, key):
    """Decrypt data using AES-256."""
    try:
        iv = data[:IV_SIZE]
        ciphertext = data[IV_SIZE:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(padded_data) + unpadder.finalize()
        return unpadded_data.decode('utf-8') if unpadded_data else None
    except Exception as e:
        print(f"[Leader] Decryption failed: {e}")
        return None

# Leader details
private_key = random.randint(1, 100)  # Leader's private key
public_key = pow(5, private_key, 23)  # Leader's public key

# Broadcast key (shared with all followers)
broadcast_key = os.urandom(AES_KEY_SIZE).hex()  # Generate a random broadcast key

def handle_follower(client, addr):
    """Handle communication with a single follower."""
    try:
        print(f"[Leader] Handling connection from {addr}")

        # Receive the follower's join message
        join_message = client.recv(BUFFER_SIZE).decode()
        follower_id, follower_public_key = join_message.split(',')
        follower_public_key = int(follower_public_key)
        print(f"[Leader] Follower {follower_id} connected with public key: {follower_public_key}")

        # Send the leader's public key
        client.send(str(public_key).encode())
        print(f"[Leader] Sent leader's public key: {public_key}")

        # Compute the shared key
        shared_key = pow(follower_public_key, private_key, 23)
        shared_key_bytes = shared_key.to_bytes(AES_KEY_SIZE, 'big')
        print(f"[Leader] Shared Key with Follower {follower_id}: {shared_key}")

        # Encrypt and send the broadcast key
        encrypted_broadcast_key = aes_encrypt(broadcast_key, shared_key_bytes, os.urandom(IV_SIZE))
        client.sendall(encrypted_broadcast_key)
        print(f"[Leader] Sent encrypted broadcast key to {follower_id}: {broadcast_key}")

        # Simulate receiving data from the follower
        while True:
            encrypted_message = client.recv(BUFFER_SIZE)
            if not encrypted_message:
                break
            decrypted_message = aes_decrypt(encrypted_message, broadcast_key.encode())
            if decrypted_message:
                print(f"[Leader] Received message from {follower_id}: {decrypted_message}")
            else:
                print(f"[Leader] Failed to decrypt message from {follower_id}")

    except Exception as e:
        print(f"[Leader] Error handling follower {addr}: {e}")
    finally:
        client.close()
        print(f"[Leader] Connection with {addr} closed.")

def start_leader():
    """Start the leader server and handle incoming connections."""
    server = None
    try:
        # Start the leader server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(LEADER_ADDRESS)
        server.listen(5)  # Allow up to 5 simultaneous connections
        print(f"[Leader] Listening for followers on {LEADER_ADDRESS}")

        while True:
            # Accept a follower connection
            client, addr = server.accept()
            print(f"[Leader] Accepted connection from {addr}")

            # Handle the follower in a separate thread
            handle_follower(client, addr)

    except KeyboardInterrupt:
        print("[Leader] Process interrupted by user.")
    except Exception as e:
        print(f"[Leader] Error: {e}")
    finally:
        if server:
            server.close()
        print("[Leader] Server closed.")

if __name__ == "__main__":
    start_leader()