
from src.ca import CertificateAuthority
from src.verifier import CertificateVerifier
from src.ml_dsa import mldsa
from datetime import datetime, timezone, timedelta

print('=== CONFIGURACIÓN ===')
# Crear CA y emitir certificados
ca = CertificateAuthority('Root CA')
root_cert = ca.initialize()

alice_pk, alice_sk = mldsa.keygen()
alice_cert = ca.issue_certificate(alice_pk, 'Alice')

print(f'CA: {ca}')
print(f'Root: {root_cert}')
print(f'Alice: {alice_cert}')
print()

# Crear verificador
verifier = CertificateVerifier(root_cert)
print(f'Verificador: {verifier}')
print()

print('=== CASO 1: Certificado válido ===')
result = verifier.verify_chain(alice_cert)
print(f'Resultado: {result}')
print()

print('=== CASO 2: Verificar solo raíz ===')
result = verifier.verify_root()
print(f'Resultado: {result}')
print()

print('=== CASO 3: Certificado expirado ===')
future_time = datetime.now(timezone.utc) + timedelta(days=400)
result = verifier.verify(alice_cert, check_time=future_time)
print(f'Resultado: {result}')
print()

print('=== CASO 4: Firma manipulada ===')
# Crear copia con firma corrupta
from src.certificate import Certificate
tampered = Certificate.from_dict(alice_cert.to_dict())
tampered.signature_value = b'\\x00' * 3309  # Firma inválida
result = verifier.verify(tampered)
print(f'Resultado: {result}')
print()

print('=== CASO 5: Issuer incorrecto ===')
# Crear otra CA
other_ca = CertificateAuthority('Other CA')
other_ca.initialize()
bob_pk, _ = mldsa.keygen()
bob_cert = other_ca.issue_certificate(bob_pk, 'Bob')

# Verificar con la CA original (debería fallar)
result = verifier.verify(bob_cert)
print(f'Resultado: {result}')
