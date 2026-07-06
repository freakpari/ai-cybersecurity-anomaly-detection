import pandas as pd
import joblib

model = joblib.load("anomaly_model.joblib")

FEATURE_COLUMNS = [
    "src_port",
    "dst_port",
    "packet_size",
    "duration_ms",
    "protocol_UDP"
]

COMMON_PORTS = [80,443,22,8080]

safe_packets = []

for size in range(100,1501,25):

    for duration in range(50,501,25):

        all_normal = True

        for src in COMMON_PORTS:

            df = pd.DataFrame([{
                "src_port":src,
                "dst_port":12345,
                "packet_size":size,
                "duration_ms":duration,
                "protocol":"TCP"
            }])

            df = pd.get_dummies(df,columns=["protocol"],drop_first=True)

            if "protocol_UDP" not in df.columns:
                df["protocol_UDP"] = 0

            df = df[FEATURE_COLUMNS]

            pred = model.predict(df)[0]

            if pred == -1:
                all_normal = False
                break

        if all_normal:
            safe_packets.append({
                "packet_size":size,
                "duration":duration
            })

safe_df = pd.DataFrame(safe_packets)

print("\nSAFE FOR ALL PORTS\n")
print(safe_df)

if len(safe_df):

    best = safe_df.sort_values(
        ["packet_size","duration"],
        ascending=False
    ).iloc[0]

    print("\nBEST SAFE PACKET")
    print(best)

else:
    print("No common safe packet found.")