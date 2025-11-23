from datetime import datetime, timezone, timedelta
from src.certificate import Certificate, Validity, SubjectPublicKeyInfo

# Crear validez (1 año)
now = datetime.now(timezone.utc)
validity = Validity(
    not_before=now,
    not_after=now + timedelta(days=365)
)

# Crear info de clave pública (dummy para test)
spki = SubjectPublicKeyInfo(
    algorithm='ML-DSA-65',
    public_key=b'dummy_key_1952_bytes'
)

# Crear certificado
cert = Certificate(
    version='v3',
    serial_number=1,
    signature_algorithm='ML-DSA-65',
    issuer_cn='Root CA',
    validity=validity,
    subject_cn='Alice',
    subject_public_key_info=spki
)

print(cert)
print(f'Self-signed: {cert.is_self_signed()}')
print(f'Valid now: {validity.is_valid_at()}')

# Test TBS dict
tbs = cert.tbs_to_dict()
print(f'TBS keys: {list(tbs.keys())}')


