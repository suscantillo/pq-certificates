"""
Tests de verificación de certificados ML-DSA-65.
Cubre casos válidos e inválidos requeridos por el proyecto.
"""

import pytest
from datetime import datetime, timezone, timedelta

from src.ca import CertificateAuthority
from src.certificate import Certificate, Validity, SubjectPublicKeyInfo
from src.serialization import serializer
from src.verifier import CertificateVerifier, VerificationError
from src.ml_dsa import mldsa


# ============================================================
# FIXTURES: Configuración reutilizable
# ============================================================

@pytest.fixture
def ca():
    """CA inicializada para tests."""
    ca = CertificateAuthority("Test Root CA")
    ca.initialize()
    return ca


@pytest.fixture
def verifier(ca):
    """Verificador con CA de confianza."""
    return CertificateVerifier(ca.root_certificate)


@pytest.fixture
def alice_keypair():
    """Par de claves para Alice."""
    return mldsa.keygen()


@pytest.fixture
def alice_cert(ca, alice_keypair):
    """Certificado válido para Alice."""
    alice_pk, _ = alice_keypair
    return ca.issue_certificate(alice_pk, "Alice")


# ============================================================
# TESTS: Casos Válidos
# ============================================================

class TestValidCertificates:
    """Tests para certificados válidos."""
    
    def test_valid_end_entity_certificate(self, verifier, alice_cert):
        """Certificado de entidad final válido debe verificar correctamente."""
        result = verifier.verify(alice_cert)
        
        assert result.is_valid
        assert result.error == VerificationError.NONE
        assert "válido" in result.message.lower()
    
    def test_valid_root_certificate(self, verifier):
        """Certificado raíz autofirmado debe verificar correctamente."""
        result = verifier.verify_root()
        
        assert result.is_valid
        assert result.error == VerificationError.NONE
    
    def test_valid_chain_verification(self, verifier, alice_cert):
        """Cadena completa (Root → Alice) debe verificar correctamente."""
        result = verifier.verify_chain(alice_cert)
        
        assert result.is_valid
        assert result.error == VerificationError.NONE
    
    def test_certificate_valid_at_boundary_start(self, ca, verifier, alice_keypair):
        """Certificado debe ser válido exactamente en notBefore."""
        alice_pk, _ = alice_keypair
        cert = ca.issue_certificate(alice_pk, "Alice")
        
        result = verifier.verify(cert, check_time=cert.validity.not_before)
        
        assert result.is_valid
    
    def test_certificate_valid_at_boundary_end(self, ca, verifier, alice_keypair):
        """Certificado debe ser válido exactamente en notAfter."""
        alice_pk, _ = alice_keypair
        cert = ca.issue_certificate(alice_pk, "Alice")
        
        result = verifier.verify(cert, check_time=cert.validity.not_after)
        
        assert result.is_valid
    
    def test_multiple_certificates_same_ca(self, ca, verifier):
        """Múltiples certificados emitidos por la misma CA deben verificar."""
        certs = []
        for name in ["Alice", "Bob", "Charlie"]:
            pk, _ = mldsa.keygen()
            cert = ca.issue_certificate(pk, name)
            certs.append(cert)
        
        for cert in certs:
            result = verifier.verify(cert)
            assert result.is_valid, f"Falló para {cert.subject_cn}"


# ============================================================
# TESTS: Casos Inválidos
# ============================================================

class TestInvalidCertificates:
    """Tests para certificados inválidos."""
    
    def test_expired_certificate(self, verifier, alice_cert):
        """Certificado expirado debe fallar verificación."""
        future_time = datetime.now(timezone.utc) + timedelta(days=400)
        
        result = verifier.verify(alice_cert, check_time=future_time)
        
        assert not result.is_valid
        assert result.error == VerificationError.CERTIFICATE_EXPIRED
    
    def test_not_yet_valid_certificate(self, verifier, alice_cert):
        """Certificado aún no válido debe fallar verificación."""
        past_time = datetime.now(timezone.utc) - timedelta(days=1)
        
        result = verifier.verify(alice_cert, check_time=past_time)
        
        assert not result.is_valid
        assert result.error == VerificationError.CERTIFICATE_NOT_YET_VALID
    
    def test_tampered_signature(self, verifier, alice_cert):
        """Certificado con firma manipulada debe fallar."""
        # Crear copia con firma corrupta
        tampered = Certificate.from_dict(alice_cert.to_dict())
        tampered.signature_value = b'\x00' * mldsa.SIG_SIZE
        
        result = verifier.verify(tampered)
        
        assert not result.is_valid
        assert result.error == VerificationError.SIGNATURE_INVALID
    
    def test_modified_subject(self, verifier, alice_cert):
        """Certificado con subject modificado debe fallar (firma inválida)."""
        tampered = Certificate.from_dict(alice_cert.to_dict())
        tampered.subject_cn = "Eve"  # Modificar subject
        
        result = verifier.verify(tampered)
        
        assert not result.is_valid
        assert result.error == VerificationError.SIGNATURE_INVALID
    
    def test_modified_serial(self, verifier, alice_cert):
        """Certificado con serial modificado debe fallar (firma inválida)."""
        tampered = Certificate.from_dict(alice_cert.to_dict())
        tampered.serial_number = 9999
        
        result = verifier.verify(tampered)
        
        assert not result.is_valid
        assert result.error == VerificationError.SIGNATURE_INVALID
    
    def test_wrong_issuer(self, verifier):
        """Certificado de otra CA debe fallar por issuer incorrecto."""
        other_ca = CertificateAuthority("Other CA")
        other_ca.initialize()
        
        bob_pk, _ = mldsa.keygen()
        bob_cert = other_ca.issue_certificate(bob_pk, "Bob")
        
        result = verifier.verify(bob_cert)
        
        assert not result.is_valid
        assert result.error == VerificationError.ISSUER_MISMATCH
    
    def test_missing_signature(self, verifier):
        """Certificado sin firma debe fallar."""
        unsigned_cert = Certificate(
            version="v3",
            serial_number=999,
            signature_algorithm="ML-DSA-65",
            issuer_cn="Test Root CA",
            validity=Validity(
                datetime.now(timezone.utc),
                datetime.now(timezone.utc) + timedelta(days=365)
            ),
            subject_cn="Unsigned",
            subject_public_key_info=SubjectPublicKeyInfo(
                algorithm="ML-DSA-65",
                public_key=b'\x00' * mldsa.PK_SIZE
            ),
            signature_value=None  # Sin firma
        )
        
        result = verifier.verify(unsigned_cert)
        
        assert not result.is_valid
        assert result.error == VerificationError.MISSING_SIGNATURE
    
    def test_truncated_signature(self, verifier, alice_cert):
        """Certificado con firma truncada debe fallar."""
        tampered = Certificate.from_dict(alice_cert.to_dict())
        tampered.signature_value = alice_cert.signature_value[:100]  # Truncar
        
        result = verifier.verify(tampered)
        
        assert not result.is_valid
        assert result.error == VerificationError.SIGNATURE_INVALID


# ============================================================
# TESTS: Verificación de Cadena
# ============================================================

class TestChainVerification:
    """Tests para verificación de cadena de confianza."""
    
    def test_chain_with_invalid_root(self, alice_cert):
        """Cadena con raíz inválido debe fallar."""
        # Crear raíz con firma corrupta
        fake_ca = CertificateAuthority("Fake CA")
        fake_root = fake_ca.initialize()
        fake_root.signature_value = b'\x00' * mldsa.SIG_SIZE
        
        verifier = CertificateVerifier(fake_root)
        result = verifier.verify_chain(alice_cert)
        
        assert not result.is_valid
        assert result.error == VerificationError.CHAIN_BROKEN
    
    def test_root_not_self_signed(self, alice_cert):
        """Raíz no autofirmado debe fallar."""
        # Crear certificado que no es autofirmado
        ca = CertificateAuthority("Real CA")
        ca.initialize()
        
        # Emitir certificado para "Fake Root" (no es autofirmado)
        fake_pk, _ = mldsa.keygen()
        fake_root = ca.issue_certificate(fake_pk, "Fake Root")
        
        verifier = CertificateVerifier(fake_root)
        result = verifier.verify_root()
        
        assert not result.is_valid
        assert result.error == VerificationError.CHAIN_BROKEN


# ==========