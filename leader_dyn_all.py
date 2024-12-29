import socket
import random
import threading

# Diffie-Hellman Parameters
g = 5  # Generator
p = 23  # Prime number
secret_key = random.randint(1, 100)

# Generate public key for Leader
public_key = pow(g, secret_key, p)
print(f"[Leader] Public Key: {public_key}")

# Set up server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 5000))
server.listen(5)

followers = {}  # Store connected followers


# Function to generate a new broadcast key
def generate_broadcast_key():
    return random.randint(1000, 9999)  # Example broadcast key


# Function to broadcast the key to all active followers
def broadcast_key(key):
    print(f"[Leader] Broadcasting new key: {key}")
    to_remove = []
    for addr, conn in followers.items():
        try:
            conn.sendall(f"KEY:{key}".encode())
        except Exception as e:
            print(f"[Leader] Failed to send key to {addr}: {e}")
            to_remove.append(addr)  # Mark this follower for removal

    # Remove failed connections
    for addr in to_remove:
        del followers[addr]
        print(f"[Leader] Removed follower {addr}")


# Function to handle each follower connection
def handle_follower(client, addr):
    global current_broadcast_key

    try:
        # Exchange public keys
        client.send(str(public_key).encode())
        follower_key = int(client.recv(1024).decode())
        shared_key = pow(follower_key, secret_key, p)

        print(f"[Leader] Follower {addr} joined with shared key: {shared_key}")

        # Add the follower to the list
        followers[addr] = client

        # Send the current broadcast key to the new follower
        client.sendall(f"KEY:{current_broadcast_key}".encode())

        # Keep connection alive
        while True:
            # Simulate receiving keep-alive messages or other interactions
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
print(f"[Leader] Initial Broadcast Key: {current_broadcast_key}")

print("[Leader] Waiting for followers to connect...")
while True:
    client, addr = server.accept()
    print(f"[Leader] Connected to follower: {addr}")
    threading.Thread(target=handle_follower, args=(client, addr)).start()

