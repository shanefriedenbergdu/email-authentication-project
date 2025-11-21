# spf_check.py
def simulate_spf_check(sender_domain: str, sender_ip: str, policy: dict):
    """
    policy: dict mapping domain -> authorized_ip (string)
    returns "PASS" or "FAIL"
    """
    authorized_ip = policy.get(sender_domain)
    if authorized_ip is None:
        record = "v=spf1 -all"
        result = "FAIL"
    else:
        record = f"v=spf1 ip4:{authorized_ip} -all"
        result = "PASS" if sender_ip == authorized_ip else "FAIL"

    print(f"SPF record for {sender_domain}: {record}")
    print(f"SPF check result: {result}")
    return result
