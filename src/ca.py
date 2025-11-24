from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from .certificate import Certificate, Validity, SubjectPublicKeyInfo
from .serialization import serializer
from .ml_dsa import mldsa


class CertificateAuthority:    
    def __init__(self, common_name: str, validity_years: int = 10):
        """
        Args:
            common_name: Nombre de la CA (ej: "Root CA")
            validity_years: Años de validez del certificado raíz
        """
        self.common_name = common_name
        self.validity_years = validity_years
        self._public_key: Optional[bytes] = None
        self._secret_key: Optional[bytes] = None
        self._root_certificate: Optional[Certificate] = None
        self._serial_counter: int = 0
    
    @property
    def is_initialized(self) -> bool:
        """Verifica si la CA está inicializada."""
        return self._secret_key is not None
    
    @property
    def root_certificate(self) -> Certificate:
        """Retorna el certificado raíz."""
        if self._root_certificate is None:
            raise RuntimeError("CA no inicializada. Llama a initialize() primero.")
        return self._root_certificate
    
    @property
    def public_key(self) -> bytes:
        """Retorna la clave pública de la CA."""
        if self._public_key is None:
            raise RuntimeError("CA no inicializada. Llama a initialize() primero.")
        return self._public_key
    
    def initialize(self) -> Certificate:
        # Generar par de claves
        self._public_key, self._secret_key = mldsa.keygen()
        
        # Crear certificado raíz (serial 0, autofirmado)
        self._serial_counter = 0
        self._root_certificate = self._create_and_sign_certificate(
            subject_cn=self.common_name,
            subject_public_key=self._public_key,
            validity_days=self.validity_years * 365
        )
        
        return self._root_certificate
    
    def _next_serial(self) -> int:
        """Genera el siguiente número de serie."""
        serial = self._serial_counter
        self._serial_counter += 1
        return serial
    
    def _create_and_sign_certificate(
        self,
        subject_cn: str,
        subject_public_key: bytes,
        validity_days: int
    ) -> Certificate:
        if self._secret_key is None:
            raise RuntimeError("CA no tiene clave secreta.")
        
        now = datetime.now(timezone.utc)
        
        certificate = Certificate(
            version="v3",
            serial_number=self._next_serial(),
            signature_algorithm=mldsa.ALGORITHM,
            issuer_cn=self.common_name,
            validity=Validity(
                not_before=now,
                not_after=now + timedelta(days=validity_days)
            ),
            subject_cn=subject_cn,
            subject_public_key_info=SubjectPublicKeyInfo(
                algorithm=mldsa.ALGORITHM,
                public_key=subject_public_key
            )
        )
        
        tbs_bytes = serializer.canonicalize_tbs(certificate)
        signature = mldsa.sign(self._secret_key, tbs_bytes)
        
        certificate.signature_value = signature
        
        return certificate
    
    def issue_certificate(
        self,
        subject_public_key: bytes,
        subject_cn: str,
        validity_days: int = 365
    ) -> Certificate:

        if not self.is_initialized:
            raise RuntimeError("CA no inicializada. Llama a initialize() primero.")
        
        if len(subject_public_key) != mldsa.PK_SIZE:
            raise ValueError(
                f"Clave pública debe ser {mldsa.PK_SIZE} bytes, "
                f"recibido {len(subject_public_key)}"
            )
        
        return self._create_and_sign_certificate(
            subject_cn=subject_cn,
            subject_public_key=subject_public_key,
            validity_days=validity_days
        )
    
    def save_root_certificate(self, filepath: str = "certs/root_ca.json") -> None:
        """Guarda el certificado raíz en un archivo."""
        serializer.save(self.root_certificate, filepath)
    
    def __repr__(self) -> str:
        status = "inicializada" if self.is_initialized else "no inicializada"
        return f"CertificateAuthority(cn='{self.common_name}', {status})"