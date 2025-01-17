from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256
from datetime import datetime, timedelta

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

with open("server.key", "wb") as key_file:
    key_file.write(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Mazowieckie"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Warsaw"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TestCompany"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    datetime.utcnow() + timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
    critical=False,
).sign(key, SHA256())

with open("server.crt", "wb") as cert_file:
    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

print("Certyfikat i klucz zostały wygenerowane: server.crt, server.key")
