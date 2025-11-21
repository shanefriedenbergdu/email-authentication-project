# verify_local_dkim.py
import sys, os, dkim

def verify_with_local_key(eml_path, pub_path):
    with open(eml_path, "rb") as f:
        data = f.read()
    with open(pub_path, "rb") as f:
        pubkey = f.read()
    ok = dkim.verify(data, dnsfunc=lambda _d, timeout=None: pubkey)
    print(f"DKIM verification for {os.path.basename(eml_path)}: {ok}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python verify_local_dkim.py <path_to_eml> <path_to_public_key>")
        sys.exit(1)
    verify_with_local_key(sys.argv[1], sys.argv[2])
