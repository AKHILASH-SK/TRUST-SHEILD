"""Certificate inspector, against real local TLS servers with certificates made on the fly."""
import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from core_engine import tls_inspector as ti


def make_cert(cn, names=None, days_old=100, valid_days=90, issuer_key=None, issuer_cn=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    now = dt.datetime.now(dt.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=days_old))
               .not_valid_after(now - dt.timedelta(days=days_old) + dt.timedelta(days=valid_days)))
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in (names or [cn])]), critical=False)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return key, cert


def serve(key, cert, tmp_path):
    kp, cp = tmp_path / "k.pem", tmp_path / "c.pem"
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cp), str(kp))
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except Exception:
                pass
    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1], lambda: (stop.set(), srv.close())


def test_a_self_signed_certificate_is_untrusted(tmp_path):
    key, cert = make_cert("localhost")
    port, stop = serve(key, cert, tmp_path)
    try:
        out = ti.inspect_certificate("localhost", port, allow_private=True)
    finally:
        stop()
    assert out["level"] == "untrusted" and out["self_signed"] is True
    assert any("self-signed" in f for f in out["flags"])


def test_a_certificate_for_another_name_is_untrusted(tmp_path):
    key, cert = make_cert("somewhere-else.example")
    port, stop = serve(key, cert, tmp_path)
    try:
        out = ti.inspect_certificate("localhost", port, allow_private=True)
    finally:
        stop()
    assert out["name_matches"] is False and out["level"] == "untrusted"


def test_a_trusted_old_certificate_is_ok_and_a_trusted_brand_new_one_is_only_noted(tmp_path):
    # the lab's own certificate authority: we hand its certificate to the checker as the trusted root
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lab CA")])
    now = dt.datetime.now(dt.timezone.utc)
    ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
               .serial_number(1).not_valid_before(now - dt.timedelta(days=400)).not_valid_after(now + dt.timedelta(days=400))
               .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                            key_encipherment=False, data_encipherment=False, key_agreement=False,
                                            encipher_only=False, decipher_only=False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
               .sign(ca_key, hashes.SHA256()))
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

    def leaf(days_old):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
                .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=days_old)).not_valid_after(now + dt.timedelta(days=60))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
                .sign(ca_key, hashes.SHA256()))
        return key, cert

    for days_old, expected in ((200, "ok"), (2, "new")):
        key, cert = leaf(days_old)
        port, stop = serve(key, cert, tmp_path)
        try:
            out = ti.inspect_certificate("localhost", port, allow_private=True, cafile=str(ca_file))
        finally:
            stop()
        assert out["level"] == expected, out


def test_private_addresses_are_not_probed_unless_allowed():
    out = ti.inspect_certificate("127.0.0.1", 443)
    assert out["level"] == "unknown"


def test_unreachable_host_is_unknown_not_an_error():
    out = ti.inspect_certificate("localhost", 1, allow_private=True, timeout=1)
    assert out["level"] == "unknown"


def test_wildcard_names_match_one_label_only():
    assert ti._host_matches("shop.example.com", ["*.example.com"])
    assert not ti._host_matches("a.b.example.com", ["*.example.com"])
    assert not ti._host_matches("example.com", ["*.example.com"])
