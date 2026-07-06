import socket
import json
import os
import pandas as pd
import joblib
import requests

HOST = 'localhost'
PORT = 9999

model = joblib.load("anomaly_model.joblib")

FEATURE_COLUMNS = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']


def pre_process_data(data):
    df = pd.DataFrame([data])
    df = pd.get_dummies(df, columns=['protocol'], drop_first=True)
    if 'protocol_UDP' not in df.columns:
        df['protocol_UDP'] = 0
    return df[FEATURE_COLUMNS]


def alert_with_llm(data):
    api_key = os.environ.get("OPENROUTER_API_KEY", "")
    if not api_key:
        print("\nAnomaly Detected!\nLabel: Anomaly\nReason: OPENROUTER_API_KEY not set\n")
        return

    response = requests.post(
        url="https://openrouter.ai/api/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": "openai/gpt-oss-120b:free",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant that labels sensor anomalies"
                },
                {
                    "role": "user",
                    "content": (
                        f"Sensor reading: {data} "
                        "Describe the type of anomaly and suggest a possible cause"
                    )
                }
            ],
            "reasoning": {"enabled": True}
        },
        timeout=30,
    )
    response.raise_for_status()
    message = response.json()['choices'][0]['message']
    content = message.get('content', str(message))
    print(f"\nAnomaly Detected!\nLabel: Anomaly\nReason: {content}\n")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    buffer = ""
    print("Client connected to server.\n")

    while True:
        chunk = s.recv(1024).decode()
        if not chunk:
            break
        buffer += chunk

        while '\n' in buffer:
            line, buffer = buffer.split('\n', 1)
            try:
                data = json.loads(line)
                print(f'Data Received:\n{data}\n')

                processed = pre_process_data(data)
                prediction = model.predict(processed)[0]

                if prediction == -1:
                    print("Classification: ANOMALY")
                    alert_with_llm(data)
                else:
                    print("Classification: NORMAL\n")

            except json.JSONDecodeError:
                print("Error decoding JSON.")
