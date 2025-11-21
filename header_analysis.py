# header_analysis.py
from email import message_from_binary_file
import sys

def analyze_headers(file_path):
    with open(file_path, "rb") as f:
        msg = message_from_binary_file(f)

    print(f"Analyzing: {file_path}")
    for k in ["From", "To", "Subject", "DKIM-Signature"]:
        v = msg.get(k)
        if v:
            print(f"{k}: {'Present' if k=='DKIM-Signature' else v}")
        else:
            print(f"{k}: {'Missing' if k=='DKIM-Signature' else ''}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 header_analysis.py <path_to_eml>")
    else:
        analyze_headers(sys.argv[1])
