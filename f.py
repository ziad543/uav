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
LEADER_ADDRESS = ('10.0.0.1', 5000)  # Leader's IP address

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
        print(f"[Follower] Decryption failed: {e}")
        return None

# Follower details
follower_id = "My_1234"
private_key = random.randint(1, 100)  # Follower's private key
public_key = pow(5, private_key, 23)  # Follower's public key

def connect_to_leader():
    client = None
    try:
        # Connect to leader
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(LEADER_ADDRESS)
        print(f"[Follower] Connected to leader at {LEADER_ADDRESS}")

        # Send join message
        join_message = f"{follower_id},{public_key}"
        client.send(join_message.encode())
        print(f"[Follower] Sent join message: {join_message}")

        # Receive the leader's public key
        leader_public_key = int(client.recv(BUFFER_SIZE).decode())
        print(f"[Follower] Leader's Public Key: {leader_public_key}")

        # Compute the shared key
        shared_key = pow(leader_public_key, private_key, 23)
        shared_key_bytes = shared_key.to_bytes(AES_KEY_SIZE, 'big')
        print(f"[Follower] Shared Key with Leader: {shared_key}")

        # Receive broadcast key (encrypted binary data)
        encrypted_key = client.recv(BUFFER_SIZE)
        print(f"[Follower] Received encrypted broadcast key: {encrypted_key}")

        # Decrypt the broadcast key
        broadcast_key = aes_decrypt(encrypted_key, shared_key_bytes)
        if broadcast_key:
            print(f"[Follower] Decrypted broadcast key: {broadcast_key}")
        else:
            print("[Follower] Failed to decrypt broadcast key.")
            return

        # Simulate sending data
        while True:
            message = "MOVE:10"
            encrypted_message = aes_encrypt(message, broadcast_key.encode(), os.urandom(IV_SIZE))
            client.sendall(encrypted_message)
            print(f"[Follower] Sent encrypted message: {message}")

    except KeyboardInterrupt:
        print("[Follower] Process interrupted by user.")
    except Exception as e:
        print(f"[Follower] Error: {e}")
    finally:
        if client:
            client.close()
        print("[Follower] Connection closed.")

if __name__ == "__main__":
    connect_to_leader()