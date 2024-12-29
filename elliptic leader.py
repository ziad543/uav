import socket
import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
import os

# Generate Leader's private key
leader_private_key = ec.generate_private_key(ec.SECP256R1())
leader_public_key = leader_private_key.public_key()
leader_public_bytes = leader_public_key.public_bytes(
    Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
)

# Set up server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 5000))
server.listen(5)
followers = {}

# Function to generate a new broadcast key
def generate_broadcast_key():
    return os.urandom(16)  # 16 bytes = 128-bit key

# Function to broadcast the key to all active followers
def broadcast_key(key):
    print(f"[Leader] Broadcasting new key: {key.hex()}")
    to_remove = []
    for addr, conn in followers.items():
        try:
            conn.sendall(f"KEY:{key.hex()}".encode())
        except Exception as e:
            print(f"[Leader] Failed to send key to {addr}: {e}")
            to_remove.append(addr)

    # Remove failed connections
    for addr in to_remove:
        del followers[addr]
        print(f"[Leader] Removed follower {addr}")

# Function to handle each follower connection
def handle_follower(client, addr):
    global current_broadcast_key

    try:
        # Exchange public keys
        client.send(leader_public_bytes)
        follower_public_bytes = client.recv(1024)
        
        # Load follower's public key
        follower_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), follower_public_bytes
        )

        # Compute shared secret
        shared_secret = leader_private_key.exchange(ec.ECDH(), follower_public_key)

        # Derive shared key using HKDF
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"leader-follower-communication",
        ).derive(shared_secret)

        print(f"[Leader] Follower {addr} joined with derived key: {derived_key.hex()}")

        # Add the follower to the list
        followers[addr] = client

        # Send the current broadcast key to the new follower
        client.sendall(f"KEY:{current_broadcast_key.hex()}".encode())

        # Keep connection alive
        while True:
            data = client.recv(1024).decode()
            if not data:
                raise ConnectionResetError("Follower disconnected")

    except Exception as e:
        print(f"[Leader] Follower {addr} disconnected: {e}")
        del followers[addr]  # Remove disconnected follower
        recalculate_and_broadcast_key()

# Function to recalculate and broadcast a new key
def recalculate_and_broadcast_key():
    global current_broadcast_key
    if followers:  # Only recalculate if there are remaining followers
        current_broadcast_key = generate_broadcast_key()
        broadcast_key(current_broadcast_key)

# Main loop
current_broadcast_key = generate_broadcast_key()  # Initial broadcast key
print(f"[Leader] Initial Broadcast Key: {current_broadcast_key.hex()}")

print("[Leader] Waiting for followers to connect...")
while True:
    client, addr = server.accept()
    print(f"[Leader] Connected to follower: {addr}")
    threading.Thread(target=handle_follower, args=(client, addr)).start()
