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


def preprocess(packet):

    df = pd.DataFrame([packet])

    df = pd.get_dummies(
        df,
        columns=["protocol"],
        drop_first=True
    )

    if "protocol_UDP" not in df.columns:
        df["protocol_UDP"] = 0

    return df[FEATURE_COLUMNS]


SRC_PORT = 443
DST_PORT = 50000
PROTOCOL = "TCP"

results = []

for packet_size in range(100,1501,25):

    for duration in range(50,501,25):

        packet = {
            "src_port":SRC_PORT,
            "dst_port":DST_PORT,
            "packet_size":packet_size,
            "duration_ms":duration,
            "protocol":PROTOCOL
        }

        pred = model.predict(preprocess(packet))[0]

        results.append({
            "packet_size":packet_size,
            "duration":duration,
            "prediction":pred
        })


df = pd.DataFrame(results)

normal = df[df.prediction==1]

print()

print("Normal packets:",len(normal))

print()

print(normal.tail(20))

best = normal.sort_values(
    ["packet_size","duration"],
    ascending=False
).iloc[0]

print("\n==============================")
print("BEST SAFE PACKET")
print("==============================")
print(best)