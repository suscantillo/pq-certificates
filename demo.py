from datetime import datetime, timezone, timedelta
from pathlib import Path

from src.ca import CertificateAuthority
from src.certificate import Certificate
from src.serialization import serializer
from src.verifier import CertificateVerifier, VerificationError
from src.ml_dsa import mldsa


def print_header(title: str) -> None:
    """Imprime un encabezado formateado."""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)


def print_certificate_info(cert: Certificate, label: str) -> None:
    print(f"\n[{label}]")
    print(f"  Subject:    {cert.subject_cn}")
    print(f"  Issuer:     {cert.issuer_cn}")
    print(f"  Serial:     {cert.serial_number}")
    print(f"  Algorithm:  {cert.signature_algorithm}")
    print(f"  Valid from: {cert.validity.not_before.strftime('%Y-%m-%d')}")
    print(f"  Valid to:   {cert.validity.not_after.strftime('%Y-%m-%d')}")
    print(f"  Self-signed: {cert.is_self_signed()}")
    if cert.signature_value:
        print(f"  Signature:  {cert.signature_value[:16].hex()}... ({len(cert.signature_value)} bytes)")


def demo_setup() -> tuple[CertificateAuthority, CertificateVerifier]:
    print_header("INICIALIZACIÓN DE LA CA")
    
    ca = CertificateAuthority("Root CA", validity_years=10)
    root_cert = ca.initialize()
    
    print(f"\nCA creada: {ca.common_name}")
    print(f"Clave pública generada: {len(ca.public_key)} bytes")
    print_certificate_info(root_cert, "Certificado Raíz")
    
    # Guardar certificado raíz
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
    ca.save_root_certificate(certs_dir / "root_ca.json")
    print(f"\ncertificado raíz guardado en: certs/root_ca.json")
    
    # Crear verificador
    verifier = CertificateVerifier(root_cert)
    print(f"Verificador inicializado con trust anchor: {root_cert.subject_cn}")
    
    return ca, verifier


def demo_issue_certificates(ca: CertificateAuthority) -> dict[str, tuple[Certificate, bytes]]:
    """Fase 2: Emisión de certificados."""
    print_header("EMISIÓN DE CERTIFICADOS")
    
    entities = {}
    certs_dir = Path("certs")
    
    for name in ["Alice", "Bob"]:
        # Generar claves para la entidad
        pk, sk = mldsa.keygen()
        print(f"\n[{name}]")
        print(f"Par de claves generado")
        print(f"Public key:  {len(pk)} bytes")
        print(f"Secret key:  {len(sk)} bytes")
        
        # Solicitar certificado a la CA
        cert = ca.issue_certificate(pk, name, validity_days=365)
        print(f"Certificado emitido (serial: {cert.serial_number})")
        
        # Guardar certificado
        filepath = certs_dir / f"{name.lower()}.json"
        serializer.save(cert, filepath)
        print(f"Guardado en: {filepath}")
        
        entities[name] = (cert, sk)
    
    return entities


def demo_valid_verification(verifier: CertificateVerifier, entities: dict) -> None:
    """Fase 3: Verificaciones válidas."""
    print_header("VERIFICACIONES VÁLIDAS")
    
    # Verificar certificado raíz
    print("\n[Test 1: Verificar certificado raíz]")
    result = verifier.verify_root()
    print(f"  Resultado: {result}")
    
    # Verificar cada certificado de entidad
    for name, (cert, _) in entities.items():
        print(f"\n[Test 2: Verificar certificado de {name}]")
        result = verifier.verify(cert)
        print(f"  Resultado: {result}")
    
    # Verificar cadena completa
    alice_cert, _ = entities["Alice"]
    print(f"\n[Test 3: Verificar cadena completa Root → Alice]")
    result = verifier.verify_chain(alice_cert)
    print(f"  Resultado: {result}")


def demo_invalid_verification(verifier: CertificateVerifier, entities: dict) -> None:
    """Fase 4: Verificaciones inválidas."""
    print_header("VERIFICACIONES INVÁLIDAS")
    
    alice_cert, _ = entities["Alice"]
    
    # Test 1: Certificado expirado
    print("\n[Test 1: Certificado expirado]")
    future = datetime.now(timezone.utc) + timedelta(days=400)
    result = verifier.verify(alice_cert, check_time=future)
    print(f"  Tiempo de verificación: {future.strftime('%Y-%m-%d')} (400 días en el futuro)")
    print(f"  Resultado: {result}")
    
    # Test 2: Certificado aún no válido
    print("\n[Test 2: Certificado aún no válido]")
    past = datetime.now(timezone.utc) - timedelta(days=1)
    result = verifier.verify(alice_cert, check_time=past)
    print(f"  Tiempo de verificación: {past.strftime('%Y-%m-%d')} (1 día en el pasado)")
    print(f"  Resultado: {result}")
    
    # Test 3: Firma manipulada
    print("\n[Test 3: Firma manipulada]")
    tampered = Certificate.from_dict(alice_cert.to_dict())
    tampered.signature_value = b'\x00' * mldsa.SIG_SIZE
    result = verifier.verify(tampered)
    print(f"  Firma reemplazada con bytes nulos")
    print(f"  Resultado: {result}")
    
    # Test 4: Subject modificado
    print("\n[Test 4: Subject modificado (intento de suplantación)]")
    tampered = Certificate.from_dict(alice_cert.to_dict())
    tampered.subject_cn = "Eve"
    result = verifier.verify(tampered)
    print(f"  Subject cambiado: Alice → Eve")
    print(f"  Resultado: {result}")
    
    # Test 5: Certificado de otra CA
    print("\n[Test 5: Certificado emitido por otra CA]")
    other_ca = CertificateAuthority("Malicious CA")
    other_ca.initialize()
    eve_pk, _ = mldsa.keygen()
    eve_cert = other_ca.issue_certificate(eve_pk, "Eve")
    result = verifier.verify(eve_cert)
    print(f"  Issuer del certificado: {eve_cert.issuer_cn}")
    print(f"  Trust anchor esperado: {verifier.trust_anchor.subject_cn}")
    print(f"  Resultado: {result}")
    
    # Test 6: Certificado sin firma
    print("\n[Test 6: Certificado sin firma]")
    tampered = Certificate.from_dict(alice_cert.to_dict())
    tampered.signature_value = None
    result = verifier.verify(tampered)
    print(f"  Resultado: {result}")


def demo_reload_and_verify(verifier: CertificateVerifier) -> None:
    """Fase 5: Cargar certificados desde disco y verificar."""
    print_header("VERIFICACIÓN DESDE ARCHIVOS")
    
    certs_dir = Path("certs")
    
    for filepath in sorted(certs_dir.glob("*.json")):
        if filepath.name == "root_ca.json":
            continue
        
        print(f"\n[Cargando: {filepath.name}]")
        cert = serializer.load(filepath)
        print(f"  Subject: {cert.subject_cn}")
        
        result = verifier.verify(cert)
        print(f"  Verificación: {result}")
    
    # Resumen de archivos generados
    print("\n[Archivos generados]")
    for filepath in sorted(certs_dir.glob("*.json")):
        size = filepath.stat().st_size
        print(f"  - {filepath.name} ({size:,} bytes)")

def main():

    print("\n" + "=" * 60)
    print(" PKI POST-CUÁNTICA CON ML-DSA-65 (FIPS 204)")
    print(" Proyecto de Criptografía - Universidad del Norte")
    print("=" * 60)
    
    # Ejecutar demo
    ca, verifier = demo_setup()
    entities = demo_issue_certificates(ca)
    demo_valid_verification(verifier, entities)
    demo_invalid_verification(verifier, entities)
    demo_reload_and_verify(verifier)

    
    print("\nDemo completado.\n")


if __name__ == "__main__":
    main()