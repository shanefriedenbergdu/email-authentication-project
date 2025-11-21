# generate_client_keys.py
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

CLIENTS = [
    {"domain": "bankofamerica.test", "selector": "default"},
    {"domain": "du-students.test",   "selector": "default"},
]

def ensure_keys(domain: str, selector: str):
    key_dir = os.path.join("keys", domain)
    os.makedirs(key_dir, exist_ok=True)
    priv_path = os.path.join(key_dir, f"{selector}.private")
    pub_path  = os.path.join(key_dir, f"{selector}.public")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        print(f"[keys] {domain}/{selector}: already exists.")
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path,  "wb") as f: f.write(pub_pem)
    print(f"[keys] {domain}/{selector}: generated.")

if __name__ == "__main__":
    for c in CLIENTS:
        ensure_keys(c["domain"], c["selector"])
