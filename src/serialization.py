import json
from pathlib import Path
from typing import Union

from .certificate import Certificate


class CertificateSerializer:
    """
    Reglas de canonicalización:
        - Orden fijo de campos (según to_dict)
        - Sin espacios entre tokens
        - Encoding UTF-8 sin BOM
    """
    
    @staticmethod
    def canonicalize_tbs(certificate: Certificate) -> bytes:

        tbs_dict = certificate.tbs_to_dict()
        canonical_json = json.dumps(
            tbs_dict,
            separators=(',', ':'),
            ensure_ascii=False
        )
        return canonical_json.encode('utf-8')
    
    @staticmethod
    def to_json(certificate: Certificate, indent: int = 2) -> str:
   
        return json.dumps(
            certificate.to_dict(),
            indent=indent,
            ensure_ascii=False
        )
    
    @staticmethod
    def from_json(json_str: str) -> Certificate:

        try:
            data = json.loads(json_str)
            return Certificate.from_dict(data)
        except (json.JSONDecodeError, KeyError) as e:
            raise ValueError(f"JSON de certificado inválido: {e}")
    
    @staticmethod
    def save(certificate: Certificate, filepath: Union[str, Path]) -> None:
   
        filepath = Path(filepath)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(CertificateSerializer.to_json(certificate))
    
    @staticmethod
    def load(filepath: Union[str, Path]) -> Certificate:

        filepath = Path(filepath)
        
        with open(filepath, 'r', encoding='utf-8') as f:
            return CertificateSerializer.from_json(f.read())



serializer = CertificateSerializer()