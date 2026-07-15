import socket
import json
import pandas as pd
import joblib
import os
from dotenv import load_dotenv
import requests 

load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

HOST = 'localhost'
PORT = 9999

try:
    model = joblib.load("anomaly_model.joblib")
    print("Defender model loaded successfully.")
except FileNotFoundError:
    print("Warning: 'anomaly_model.joblib' not found. Please run the training script first.")
    model = None

def pre_process_data(data):
    df = pd.DataFrame([data])
    df_processed = pd.get_dummies(df, columns=['protocol'], drop_first=True)
    expected_cols = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']
    for col in expected_cols:
        if col not in df_processed.columns:
            df_processed[col] = 0
            
    df_processed = df_processed[expected_cols]
    return df_processed

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
                print(f'Data Received: {data}')

                if model is not None:
                    processed_df = pre_process_data(data)
                    prediction = model.predict(processed_df)[0] 
                    
                    if prediction == -1:
                        print("--> Status: ANOMALY DETECTED")
                        
                        if not GROQ_API_KEY:
                            print("[Error] GROQ_API_KEY not found in .env file.")
                        else:
                            url = "https://api.groq.com/openai/v1/chat/completions"
                            headers = {
                                "Authorization": f"Bearer {GROQ_API_KEY}",
                                "Content-Type": "application/json",
                            }
                            
                            payload = {
                                "model": "openai/gpt-oss-120b",
                                "messages": [
                                    {
                                        "role": "system",
                                        "content": "You are a network security assistant. Analyze the anomalous network event and supply a concise cause assessment."
                                    },
                                    {
                                        "role": "user",
                                        "content": f"The following reading was flagged as anomalous: {json.dumps(data)}. Explain potential issues."
                                    }
                                ]
                            }
                            
                            try:
                                response = requests.post(
                                    url=url,
                                    headers=headers,
                                    data=json.dumps(payload),
                                    timeout=10
                                )
                                
                                if response.status_code == 200:
                                    res_json = response.json()
                                    reason = res_json['choices'][0]['message']['content'].strip()
                                    
                                    print(f"\n--- Anomaly Alert (Groq Analysis) ---")
                                    print(f"Reason: {reason}\n")
                                else:
                                    print(f"Could not fetch LLM explanation (HTTP {response.status_code}).")
                                    print(f"Details: {response.text}")
                            except Exception as e:
                                print(f"Error querying Groq API: {e}")
                        
                    else:
                        print("Status: Normal\n")
                else:
                    print("Model file is missing. Skipping classification.")

            except json.JSONDecodeError:
                print("Error decoding JSON.")