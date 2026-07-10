import socket
import time
import json
import random
import joblib
import pandas as pd
import numpy as np

HOST = 'localhost'
PORT = 9999

TOTAL_PAYLOAD_SIZE = 10000
TOTAL_DURATION_MS = 4000
COMMON_PORTS = [80, 443, 22, 8080]

try:
    surrogate_model = joblib.load("surrogate_model.joblib")
    print("Successfully loaded the local surrogate model.")
except FileNotFoundError:
    print("Error: surrogate_model.joblib not found. Run train_adversary.ipynb first.")
    exit(1)


def find_optimal_packet_parameters():
    """
    Finds the largest values for 'packet_size' and 'duration_ms'
    where the surrogate_model still predicts a label of 1 (normal)
    across ALL common source ports.
    """
    best_size = 100
    best_duration = 50

    for size in range(100, 1500, 10):
        for duration in range(50, 500, 5):
            
            all_ports_safe = True
            for port in COMMON_PORTS:
                query_df = pd.DataFrame([[port, size, duration]], columns=['src_port', 'packet_size', 'duration_ms'])
                pred = surrogate_model.predict(query_df)[0]
                if pred != 1:
                    all_ports_safe = False
                    break
            
            if all_ports_safe:
                if size > best_size or (size == best_size and duration > best_duration):
                    best_size = size
                    best_duration = duration

    safe_size = int(best_size * 0.90)
    safe_duration = int(best_duration * 0.90)

    return max(100, safe_size), max(50, safe_duration)


def evade_and_transmit(conn, max_safe_size, max_safe_duration):
    """
    Using the calculated max_safe_size and max_safe_duration, split
    the TOTAL_PAYLOAD_SIZE and TOTAL_DURATION_MS and send them safely.
    """
    sent_payload = 0
    sent_duration = 0

    print(f"Optimal parameters from surrogate -> Size: {max_safe_size}, Duration: {max_safe_duration}")
    print("Beginning optimized evasion attack transmission...")

    while sent_payload < TOTAL_PAYLOAD_SIZE or sent_duration < TOTAL_DURATION_MS:
        current_size = min(max_safe_size, TOTAL_PAYLOAD_SIZE - sent_payload)
        current_duration = min(max_safe_duration, TOTAL_DURATION_MS - sent_duration)
        
        if current_size < 300:
            current_size = 300
        if current_duration < 150:
            current_duration = 150

        packet = {
            "src_port": random.choice(COMMON_PORTS),
            "dst_port": 8080,
            "packet_size": int(current_size),
            "duration_ms": int(current_duration),
            "protocol": "TCP"
        }
        
        conn.sendall((json.dumps(packet) + '\n').encode())
        
        sent_payload += current_size
        sent_duration += current_duration
        
        print(f"Sent packet: Size={current_size}, Duration={current_duration} | "
              f"Progress: Payload={sent_payload}/{TOTAL_PAYLOAD_SIZE}, Duration={sent_duration}/{TOTAL_DURATION_MS}")
        
        time.sleep(0.1)


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Adversary Server running and waiting for client to connect...")
conn, addr = server.accept()
print(f"Connected by defender client at {addr}")

try:
    max_size, max_duration = find_optimal_packet_parameters()
    evade_and_transmit(conn, max_size, max_duration)
    print("Attack transmission completed successfully!")
except KeyboardInterrupt:
    print("Adversary server stopped.")
finally:
    conn.close()
    server.close()