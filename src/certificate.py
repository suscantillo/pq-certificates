from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class SubjectPublicKeyInfo:
    """Información de clave pública del sujeto."""
    algorithm: str
    public_key: bytes
    
    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "publicKey": self.public_key.hex()
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SubjectPublicKeyInfo":
        return cls(
            algorithm=data["algorithm"],
            public_key=bytes.fromhex(data["publicKey"])
        )


@dataclass
class Validity:
    """Período de validez del certificado."""
    not_before: datetime
    not_after: datetime
    
    def to_dict(self) -> dict:
        return {
            "notBefore": self.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "notAfter": self.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Validity":
        return cls(
            not_before=datetime.strptime(data["notBefore"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc),
            not_after=datetime.strptime(data["notAfter"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        )
    
    def is_valid_at(self, check_time: Optional[datetime] = None) -> bool:
        """Verifica si el certificado es válido en un momento dado."""
        if check_time is None:
            check_time = datetime.now(timezone.utc)
        return self.not_before <= check_time <= self.not_after


@dataclass
class Certificate:
    """
    Certificado X.509 simplificado para ML-DSA-65.
    
    Campos TBS (To-Be-Signed):
        - version, serial_number, signature_algorithm
        - issuer_cn, validity, subject_cn, subject_public_key_info
    
    Campo de firma:
        - signature_value
    """
    
    # TBS fields
    version: str
    serial_number: int
    signature_algorithm: str
    issuer_cn: str  # issuer Common Name
    validity: Validity
    subject_cn: str  # subject Common Name
    subject_public_key_info: SubjectPublicKeyInfo
    
    # Signature (None hasta que se firme)
    signature_value: Optional[bytes] = field(default=None)
    
    def tbs_to_dict(self) -> dict:
        return {
            "version": self.version,
            "serialNumber": self.serial_number,
            "signature": {"algorithm": self.signature_algorithm},
            "issuer": {"commonName": self.issuer_cn},
            "validity": self.validity.to_dict(),
            "subject": {"commonName": self.subject_cn},
            "subjectPublicKeyInfo": self.subject_public_key_info.to_dict()
        }
    
    def to_dict(self) -> dict:
        """Retorna el certificado completo como diccionario."""
        cert_dict = self.tbs_to_dict()
        if self.signature_value is not None:
            cert_dict["signatureValue"] = self.signature_value.hex()
        return cert_dict
    
    @classmethod
    def from_dict(cls, data: dict) -> "Certificate":
        """Construye un Certificate desde un diccionario."""
        signature_value = None
        if "signatureValue" in data:
            signature_value = bytes.fromhex(data["signatureValue"])
        
        return cls(
            version=data["version"],
            serial_number=data["serialNumber"],
            signature_algorithm=data["signature"]["algorithm"],
            issuer_cn=data["issuer"]["commonName"],
            validity=Validity.from_dict(data["validity"]),
            subject_cn=data["subject"]["commonName"],
            subject_public_key_info=SubjectPublicKeyInfo.from_dict(data["subjectPublicKeyInfo"]),
            signature_value=signature_value
        )
    
    def is_self_signed(self) -> bool:
       
        return self.issuer_cn == self.subject_cn
    
    def __repr__(self) -> str:
        return (
            f"Certificate(subject='{self.subject_cn}', "
            f"issuer='{self.issuer_cn}', "
            f"serial={self.serial_number})"
        )