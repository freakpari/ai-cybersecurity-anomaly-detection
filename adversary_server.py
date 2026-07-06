import socket
import time
import json
import joblib
import pandas as pd

HOST = "localhost"
PORT = 9999

TOTAL_PAYLOAD_SIZE = 10000

try:
    surrogate_model = joblib.load("surrogate_model.joblib")
    print("Successfully loaded surrogate model.")
except FileNotFoundError:
    print("surrogate_model.joblib not found.")
    exit()


def find_best_packet():
    """
    Search the surrogate model offline and return the
    largest packet_size and largest duration that are
    predicted as NORMAL.
    """

    for packet_size in range(1500, 99, -50):

        for duration in range(500, 49, -25):

            sample = pd.DataFrame(
                [[packet_size, duration]],
                columns=[
                    "packet_size",
                    "duration_ms"
                ]
            )

            prediction = surrogate_model.predict(sample)[0]

            if prediction == 1:
                return packet_size, duration

    return None


def evade_and_transmit(conn):

    print("\nSearching optimal packet using surrogate model...")

    result = find_best_packet()

    if result is None:
        print("No safe packet found.")
        return

    max_safe_size, max_safe_duration = result

    print(f"Optimal packet found: size={max_safe_size}, duration={max_safe_duration}")
    print("Starting evasive transmission...\n")

    payload_sent = 0

    while payload_sent < TOTAL_PAYLOAD_SIZE:

        current_size = min(
            max_safe_size,
            TOTAL_PAYLOAD_SIZE - payload_sent
        )

        packet = {
            "src_port": 80,
            "dst_port": 80,
            "packet_size": current_size,
            "duration_ms": max_safe_duration,
            "protocol": "TCP"
        }

        conn.sendall(
            (json.dumps(packet) + "\n").encode()
        )

        print(packet)

        payload_sent += current_size

        time.sleep(0.1)

    print("\nAttack finished successfully.")
    print(f"Payload sent: {payload_sent} bytes")


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Waiting for defender...")

conn, addr = server.accept()

print("Connected:", addr)

try:

    evade_and_transmit(conn)

except KeyboardInterrupt:

    print("Stopped.")

finally:
    conn.close()
    server.close()