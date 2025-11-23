from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from .certificate import Certificate
from .serialization import serializer
from .ml_dsa import mldsa

# En este modulo si se comentaran casi todos los metodos, para no perderme
class VerificationError(Enum):
    NONE = "Verificación exitosa"
    SIGNATURE_INVALID = "Firma inválida"
    CERTIFICATE_EXPIRED = "Certificado expirado"
    CERTIFICATE_NOT_YET_VALID = "Certificado aún no válido"
    ISSUER_MISMATCH = "Issuer no coincide con CA"
    MISSING_SIGNATURE = "Certificado sin firma"
    INVALID_PUBLIC_KEY = "Clave pública inválida"
    CHAIN_BROKEN = "Cadena de confianza rota"


@dataclass
class VerificationResult:
    """Resultado de una verificación de certificado."""
    is_valid: bool
    error: VerificationError
    message: str
    
    @classmethod
    def success(cls) -> "VerificationResult":
        return cls(
            is_valid=True,
            error=VerificationError.NONE,
            message="Certificado válido"
        )
    
    @classmethod
    def failure(cls, error: VerificationError, details: str = "") -> "VerificationResult":
        message = error.value
        if details:
            message = f"{message}: {details}"
        return cls(
            is_valid=False,
            error=error,
            message=message
        )
    
    def __bool__(self) -> bool:
        return self.is_valid
    
    def __repr__(self) -> str:
        status = "VALIDO" if self.is_valid else "INVALIDO"
        return f"VerificationResult({status}: {self.message})"


class CertificateVerifier:
    
    def __init__(self, trust_anchor: Certificate):
        """
        Args:
            trust_anchor: Certificado raíz de confianza (CA)
        """
        self._trust_anchor = trust_anchor
        self._ca_public_key = trust_anchor.subject_public_key_info.public_key
        self._ca_common_name = trust_anchor.subject_cn
    
    @property
    def trust_anchor(self) -> Certificate:
        """Retorna el certificado raíz de confianza."""
        return self._trust_anchor
    
    def verify(
        self,
        certificate: Certificate,
        check_time: Optional[datetime] = None
    ) -> VerificationResult:
        """
        Verifica un certificado contra la CA de confianza.
        
        Validaciones:
            1. Certificado tiene firma
            2. Issuer coincide con CA
            3. Firma es válida (ML-DSA-65)
            4. Certificado está dentro del período de validez
        
        Args:
            certificate: Certificado a verificar
            check_time: Momento de verificación (default: ahora)
            
        Returns:
            VerificationResult: Resultado con estado y detalles
        """
        if check_time is None:
            check_time = datetime.now(timezone.utc)
        
        # 1. Verificar que tiene firma
        if certificate.signature_value is None:
            return VerificationResult.failure(
                VerificationError.MISSING_SIGNATURE
            )
        
        # 2. Verificar issuer
        if certificate.issuer_cn != self._ca_common_name:
            return VerificationResult.failure(
                VerificationError.ISSUER_MISMATCH,
                f"esperado '{self._ca_common_name}', recibido '{certificate.issuer_cn}'"
            )
        
        # 3. Verificar firma
        tbs_bytes = serializer.canonicalize_tbs(certificate)
        signature_valid = mldsa.verify(
            self._ca_public_key,
            tbs_bytes,
            certificate.signature_value
        )
        
        if not signature_valid:
            return VerificationResult.failure(
                VerificationError.SIGNATURE_INVALID
            )
        
        # 4. Verificar período de validez
        validity = certificate.validity
        
        if check_time < validity.not_before:
            return VerificationResult.failure(
                VerificationError.CERTIFICATE_NOT_YET_VALID,
                f"válido desde {validity.not_before.isoformat()}"
            )
        
        if check_time > validity.not_after:
            return VerificationResult.failure(
                VerificationError.CERTIFICATE_EXPIRED,
                f"expiró el {validity.not_after.isoformat()}"
            )
        
        return VerificationResult.success()
    
    def verify_root(self, check_time: Optional[datetime] = None) -> VerificationResult:
        """
        Verifica el certificado raíz (autofirmado).
        
        Args:
            check_time: Momento de verificación (default: ahora)
            
        Returns:
            VerificationResult: Resultado de la verificación
        """
        if check_time is None:
            check_time = datetime.now(timezone.utc)
        
        root = self._trust_anchor
        
        # Verificar que es autofirmado
        if not root.is_self_signed():
            return VerificationResult.failure(
                VerificationError.CHAIN_BROKEN,
                "certificado raíz no es autofirmado"
            )
        
        # Verificar firma del raíz contra sí mismo
        if root.signature_value is None:
            return VerificationResult.failure(
                VerificationError.MISSING_SIGNATURE
            )
        
        tbs_bytes = serializer.canonicalize_tbs(root)
        signature_valid = mldsa.verify(
            self._ca_public_key,
            tbs_bytes,
            root.signature_value
        )
        
        if not signature_valid:
            return VerificationResult.failure(
                VerificationError.SIGNATURE_INVALID,
                "firma del certificado raíz inválida"
            )
        
        # Verificar validez temporal
        if check_time < root.validity.not_before:
            return VerificationResult.failure(
                VerificationError.CERTIFICATE_NOT_YET_VALID
            )
        
        if check_time > root.validity.not_after:
            return VerificationResult.failure(
                VerificationError.CERTIFICATE_EXPIRED
            )
        
        return VerificationResult.success()
    
    def verify_chain(
        self,
        certificate: Certificate,
        check_time: Optional[datetime] = None
    ) -> VerificationResult:
        """
        Verifica la cadena completa: Root → End Entity.
        
        Args:
            certificate: Certificado de entidad final
            check_time: Momento de verificación
            
        Returns:
            VerificationResult: Resultado de la verificación completa
        """
        # Primero verificar el raíz
        root_result = self.verify_root(check_time)
        if not root_result:
            return VerificationResult.failure(
                VerificationError.CHAIN_BROKEN,
                f"raíz inválido: {root_result.message}"
            )
        
        # Luego verificar el certificado de entidad
        return self.verify(certificate, check_time)
    
    def __repr__(self) -> str:
        return f"CertificateVerifier(trust_anchor='{self._ca_common_name}')"