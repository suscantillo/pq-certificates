# PKI Post-Cuántica con ML-DSA-65

Implementación de una Autoridad Certificadora (CA) que emite certificados firmados con Dilithium (ML-DSA-65) y un verificador de cadena de confianza.

**Curso:** Criptografía  
**Universidad del Norte**  
**Autores:** Jesús Cantillo, Juan Povea, Yovany Zhu

---

## Descripción

Este proyecto implementa una PKI mínima utilizando el algoritmo de firma digital post-cuántico ML-DSA-65 (FIPS 204), demostrando:

- Generación de claves ML-DSA-65
- Emisión de certificados autofirmados (CA raíz)
- Emisión de certificados de entidad final
- Verificación de cadena de confianza
- Detección de certificados inválidos o manipulados

## Requisitos

- Python 3.10+
- pip

## Instalación
```bash
git clone <repositorio>
cd pq-certificates

pip install -r requirements.txt
```

## Uso

### Ejecutar demostración completa
```bash
python demo.py
```

### Ejecutar tests
```bash
pytest tests/ -v
```

## Estructura del Proyecto
```
.
├── certs/                  # Certificados generados
├── demo.py                 # Demostración del flujo completo
├── conftest.py             # Configuración de pytest
├── requirements.txt        # Dependencias
├── README.md
├── src/
│   ├── __init__.py
│   ├── ml_dsa.py           # Wrapper ML-DSA-65
│   ├── certificate.py      # Modelo de certificado
│   ├── serialization.py    # Canonicalización JSON
│   ├── ca.py               # Autoridad Certificadora
│   └── verifier.py         # Verificador de cadena
└── tests/
    ├── __init__.py
    └── test_verifier.py    # Tests de verificación
```

## Arquitectura

### Cadena de Confianza
```
┌─────────────────┐
│    Root CA      │  (autofirmado)
│   ML-DSA-65     │
└────────┬────────┘
         │ firma
         ▼
┌─────────────────┐
│  End Entity     │  (Alice, Bob, ...)
│   Certificate   │
└─────────────────┘
```

### Tamaños ML-DSA-65

| Componente     | Tamaño    |
|----------------|-----------|
| Clave pública  | 1,952 bytes |
| Clave privada  | 4,032 bytes |
| Firma          | 3,309 bytes |

## Casos de Prueba

### Verificaciones Válidas
- Certificado de entidad final correctamente firmado
- Certificado raíz autofirmado
- Cadena completa Root → End Entity

### Verificaciones Inválidas
- Certificado expirado
- Certificado aún no válido
- Firma manipulada
- Subject modificado (suplantación)
- Certificado de CA no confiable
- Certificado sin firma

## Perfil de Certificado

Formato JSON simplificado basado en X.509:
```json
{
  "version": "v3",
  "serialNumber": 1,
  "signature": {"algorithm": "ML-DSA-65"},
  "issuer": {"commonName": "Root CA"},
  "validity": {
    "notBefore": "2025-11-23T12:00:00Z",
    "notAfter": "2026-11-23T12:00:00Z"
  },
  "subject": {"commonName": "Alice"},
  "subjectPublicKeyInfo": {
    "algorithm": "ML-DSA-65",
    "publicKey": "48f2a1c3..."
  },
  "signatureValue": "9a3c5e2f..."
}
```

## Limitaciones

- Cadena de un solo nivel (sin CAs intermedias)
- Sin revocación (CRL/OCSP)
- Serialización JSON (no ASN.1 DER)
- Sin integración TLS

## Referencias

- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [dilithium-py](https://github.com/GiacomoPope/dilithium-py)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)