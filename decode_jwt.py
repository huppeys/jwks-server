import base64
from datetime import datetime, timezone

token = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImV4YW1wbGVfa2V5XzEiLCJ0eXAiOiJKV1QifQ.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxNzcxMjA2MzQxfQ.Bb47wAZmIq_043qqvQ8Rhe4DdELEJvF9oixOwc1rkIOqMSG3lqjIWpUhSx39nXSiUpfS7rh2C5GKpeCjVMFSy-f6qhpaFl3sjsS74hFOiJc9cy-PEf-boS4BECtC9MfbYoMbwzC5dqvm_OM64xQJ8Auq52jh7E9AQdY1HjQ3cuMMApdbMVzmoFrDPD8JV6v3tGeUcQ1YuFJEx2hkcoV5NgtRPAd0pyzMMu9jMlmz_voFU6dAjacoP3SYTp2bpgGVTkj63kMM7QuLHdLTgi1dtVl0sb3YmQBZ3W80uMcG_z_shTffiZuAstxOZ0HZZqTaH6dDjCby-KMQdWdte0dKjQ"

# Split the JWT
header, payload, signature = token.split('.')

# Decode the header and payload
decoded_header = base64.urlsafe_b64decode(header + '==').decode('utf-8')
decoded_payload = base64.urlsafe_b64decode(payload + '==').decode('utf-8')

print("Decoded Header:", decoded_header)
print("Decoded Payload:", decoded_payload)

# Check the expiration time
import json
payload_data = json.loads(decoded_payload)  # Parse the payload to access expiration
exp_time = payload_data['exp']

# Convert expiration time to a readable format
readable_time = datetime.fromtimestamp(exp_time, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
print("Expiration Time:", readable_time)

