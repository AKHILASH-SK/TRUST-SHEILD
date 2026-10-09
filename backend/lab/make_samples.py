"""Writes the lab's sample emails to backend/lab/samples/ so they can be uploaded to the portal:  python -m lab.make_samples"""
import os

from lab.mail_lab import LabWorld, genuine_bank_email, forged_bank_email, build_message, BANK_DOMAIN, ATTACKER_IP

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def main():
    os.makedirs(OUT, exist_ok=True)
    world = LabWorld()
    samples = {
        "1_genuine_bank_email.eml": genuine_bank_email(world),
        "2_forged_bank_email.eml": forged_bank_email(),
        "3_forged_but_forwarded_through_a_list.eml": build_message(
            f'"Bank Security" <alerts@{BANK_DOMAIN}>', ATTACKER_IP, subject="Fwd: account notice",
            extra_headers="List-Id: <friends.example.org>\r\nARC-Seal: i=1"),
    }
    for name, raw in samples.items():
        with open(os.path.join(OUT, name), "wb") as fh:
            fh.write(raw)
        print("wrote", os.path.join(OUT, name))


if __name__ == "__main__":
    main()
