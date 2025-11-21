# multi_client_demo.py
import base64
from cryptography.hazmat.primitives import serialization
import os, time, glob, smtplib
from email.message import EmailMessage
import dkim
from spf_check import simulate_spf_check

MAIL_HOST, MAIL_PORT = "127.0.0.1", 1025
SENDER_IP = "127.0.0.1"  # your local host in this demo

CLIENTS = [
    {
        "name": "BankOfAmerica (Legitimate)",
        "domain": "bankofamerica.test",
        "selector": "default",
        "from_addr": "alerts@bankofamerica.test",
        "envelope_from": "noreply@bankofamerica.test",
        "to_addr": "victim@local.test",
        "spf_authorized_ip": "127.0.0.1",  # our IP -> SPF PASS
        "send_mode": "signed",             # legit sender (DKIM signed)
    },
    {
        "name": "DU Students (Spoof Attempt)",
        "domain": "du-students.test",
        "selector": "default",
        "from_addr": "financial-aid@du-students.test",
        "envelope_from": "it@du-students.test",
        "to_addr": "victim@local.test",
        "spf_authorized_ip": "203.0.113.5",  # not our IP -> SPF FAIL
        "send_mode": "unsigned",             # attacker/impersonator (no DKIM)
    },
]

def key_paths(domain: str, selector: str):
    keydir = os.path.join("keys", domain)
    return (
        os.path.join(keydir, f"{selector}.private"),
        os.path.join(keydir, f"{selector}.public"),
    )

def send_unsigned(frm: str, to: str):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = frm, to, "Unsigned Email Test"
    msg.set_content("This is an unsigned (spoofed) message.")
    with smtplib.SMTP(MAIL_HOST, MAIL_PORT) as s:
        s.send_message(msg)

def build_signed_bytes(frm: str, to: str, domain: str, selector: str, priv_path: str):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = frm, to, "DKIM-Signed Email Test"
    msg.set_content("This message includes DKIM protection.")
    with open(priv_path, "rb") as f:
        privkey = f.read()
    raw = msg.as_bytes().replace(b"\n", b"\r\n")  # normalize to CRLF before signing
    sig = dkim.sign(
        message=raw,
        selector=selector.encode(),
        domain=domain.encode(),
        privkey=privkey,
        include_headers=[b"from", b"to", b"subject"],
        canonicalize=(b"relaxed", b"relaxed"),
    )
    return sig + raw

def dns_txt_from_pem(pub_path: str) -> bytes:
    """
    Load a PEM public key and return a DKIM TXT record:
    v=DKIM1; k=rsa; p=<base64 DER SubjectPublicKeyInfo>
    """
    with open(pub_path, "rb") as f:
        pub_pem = f.read()
    pub = serialization.load_pem_public_key(pub_pem)
    der = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    p_b64 = base64.b64encode(der).decode("ascii")
    # minimal valid record for dkimpy
    return f"v=DKIM1; k=rsa; p={p_b64}".encode("ascii")


def send_signed(envelope_from: str, to: str, signed_bytes: bytes):
    with smtplib.SMTP(MAIL_HOST, MAIL_PORT) as s:
        s.sendmail(envelope_from, [to], signed_bytes)

def verify_dkim_bytes(signed_bytes: bytes, pub_path: str):
    txt = dns_txt_from_pem(pub_path)
    normalized = signed_bytes.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return dkim.verify(normalized, dnsfunc=lambda _d, timeout=None: txt)


def verify_dkim_file(eml_path: str, pub_path: str):
    with open(eml_path, "rb") as f:
        data = f.read()
    txt = dns_txt_from_pem(pub_path)
    normalized = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    return dkim.verify(normalized, dnsfunc=lambda _d, timeout=None: txt)


def latest_saved_eml():
    time.sleep(0.8)  # let the server flush
    files = sorted(glob.glob("messages/msg_*.eml"))
    return files[-1] if files else None

def run_for_client(c):
    print(f"\n Client: {c['name']} ({c['domain']})")

    spf_policy = {c["domain"]: c["spf_authorized_ip"]}
    spf_result = simulate_spf_check(c["domain"], SENDER_IP, spf_policy)

    dkim_in_memory = None
    dkim_on_disk = None
    saved_path = None

    if c["send_mode"] == "unsigned":
        send_unsigned(c["from_addr"], c["to_addr"])
        print("Unsigned message sent.")
        saved_path = latest_saved_eml()
        if saved_path:
            _, pub_path = key_paths(c["domain"], c["selector"])
            dkim_on_disk = verify_dkim_file(saved_path, pub_path)

    elif c["send_mode"] == "signed":
        priv_path, pub_path = key_paths(c["domain"], c["selector"])
        signed_bytes = build_signed_bytes(
            c["from_addr"], c["to_addr"], c["domain"], c["selector"], priv_path
        )
        # in-memory verify (expected True on same bytes)
        dkim_in_memory = verify_dkim_bytes(signed_bytes, pub_path)
        # deliver to mailbox for screenshots / header inspection
        send_signed(c["envelope_from"], c["to_addr"], signed_bytes)
        print("DKIM-signed message sent.")
        saved_path = latest_saved_eml()
        if saved_path:
            dkim_on_disk = verify_dkim_file(saved_path, pub_path)

    print("\nResults:")
    print(f"SPF (policy)        : {spf_result}")
    if dkim_in_memory is not None:
        print(f"DKIM (in-memory)    : {dkim_in_memory}")
    if dkim_on_disk is not None:
        print(f"DKIM (saved .eml)   : {dkim_on_disk}")
    if saved_path:
        print(f"Saved file          : {saved_path}")

    trusted = (spf_result == "PASS") and (dkim_in_memory is True or dkim_on_disk is True)
    print(f"Status              : {'Trusted' if trusted else 'Suspicious/Rejected'}")

if __name__ == "__main__":
    print("Email Authentication — Multi-Client Demonstration ===")
    for client in CLIENTS:
        run_for_client(client)
    print("\n Summary ")
    print("BankOfAmerica: Authorized sender with SPF+DKIM -> should be Trusted.")
    print("DU Students: Spoof attempt (SPF fail, no DKIM) -> should be Rejected.")
