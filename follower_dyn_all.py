import socket
import random
import hashlib

# Diffie-Hellman Parameters
g = 5  # Generator
p = 23  # Prime numberimport socket
import random

# Diffie-Hellman Parameters
g = 5  # Generator
p = 23  # Prime number
secret_key = random.randint(1, 100)

# Generate public key for Follower
public_key = pow(g, secret_key, p)
print(f"[Follower] Public Key: {public_key}")

# Connect to the Leader
leader_ip = '172.16.0.1'  # Replace with Leader's IP
leader_port = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((leader_ip, leader_port))

# Exchange keys
leader_key = int(client.recv(1024).decode())
client.send(str(public_key).encode())
shared_key = pow(leader_key, secret_key, p)

print(f"[Follower] Shared key with Leader: {shared_key}")

# Receive and update the broadcast key
while True:
    data = client.recv(1024).decode()
    if data.startswith("KEY:"):
        broadcast_key = data.split(":")[1]
        print(f"[Follower] Received new broadcast key: {broadcast_key}")

secret_key = random.randint(1, 100)

# Generate public key
public_key = pow(g, secret_key, p)
print(f"[Follower] Public Key: {public_key}")

# Connect to the leader
leader_ip = '172.16.0.1'  # Replace with Leader's IP
leader_port = 5000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((leader_ip, leader_port))

# Exchange keys
leader_key = int(client.recv(1024).decode())
client.send(str(public_key).encode())
shared_key = pow(leader_key, secret_key, p)

print(f"[Follower] Shared key with leader: {shared_key}")

# Keep the connection open
while True:
    pass

