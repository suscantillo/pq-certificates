# PKI Post-Cuántica con ML-DSA-65

Implementación de una Infraestructura de Clave Pública (PKI) mínima utilizando el algoritmo de firma digital post-cuántico ML-DSA-65 (FIPS 204).

## Descripción General

Este proyecto demuestra una jerarquía de certificados de dos niveles donde una CA raíz autofirmada emite certificados de entidad final, todos firmados usando el algoritmo de firma basado en retículos modulares estandarizado por NIST.

**Curso:** Criptografía — Universidad del Norte  
**Autores:** Jesús Cantillo · Juan Povea · Yovany Zhu

## Características

- Generación de claves, firma y verificación con ML-DSA-65
- Emisión de certificado raíz autofirmado
- Emisión de certificados de entidad final
- Validación de cadena de confianza
- Detección de certificados manipulados, expirados o no autorizados
- Formato de certificado JSON con canonicalización determinista

## Requisitos

- Python ≥ 3.10
- pip

## Inicio Rápido
```bash
# Clonar e instalar
git clone <repositorio>
cd pq-certificates
pip install -r requirements.txt

# Ejecutar demostración
python demo.py

# Ejecutar tests
pytest tests/ -v
```

## Estructura del Proyecto
```
pq-certificates/
├── src/
│   ├── ml_dsa.py           # Wrapper criptográfico ML-DSA-65
│   ├── certificate.py      # Modelo de datos del certificado
│   ├── serialization.py    # Canonicalización JSON
│   ├── ca.py               # Autoridad Certificadora
│   └── verifier.py         # Verificador de cadena
├── tests/
│   └── test_verifier.py    # 16 casos de prueba
├── certs/                  # Certificados generados
└── demo.py                 # Demostración completa
```

## Cadena de Confianza
```
┌──────────────────────┐
│      Root CA         │  ← Autofirmado (serial: 0)
│     ML-DSA-65        │     Validez: 10 años
└──────────┬───────────┘
           │ firma
           ▼
┌──────────────────────┐
│   Entidad Final      │  ← Emitido por Root CA
│  (Alice, Bob, ...)   │     Validez: 1 año
└──────────────────────┘
```

## Parámetros ML-DSA-65

| Componente    | Tamaño        |
|---------------|---------------|
| Clave Pública | 1,952 bytes   |
| Clave Privada | 4,032 bytes   |
| Firma         | 3,309 bytes   |
| Hash          | 32 bytes (SHA3-256) |

---

## Proceso de Firma de Certificados

Cuando la CA emite un certificado, ejecuta el siguiente proceso:

### Paso 1: Construcción del TBS (To-Be-Signed)

Se construye la estructura de datos que será firmada, conteniendo todos los campos del certificado excepto la firma:
```
TBS = {
    version,
    serialNumber,
    signature.algorithm,
    issuer,
    validity,
    subject,
    subjectPublicKeyInfo
}
```

### Paso 2: Canonicalización JSON

El TBS se serializa a JSON con formato determinista (sin espacios, orden fijo de campos):
```
{"version":"v3","serialNumber":1,"signature":{"algorithm":"ML-DSA-65"},...}
```

### Paso 3: Hash SHA3-256

Se computa el hash criptográfico del JSON canónico:
```
hash = SHA3-256(canonical_json)  →  32 bytes
```

### Paso 4: Firma ML-DSA-65

La CA firma el hash con su clave secreta:
```
σ = ML-DSA.Sign(sk_CA, hash)  →  3,309 bytes
```

### Diagrama del Proceso
```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐     ┌─────────────────┐
│   TBS Fields    │ ──▶ │ JSON Canónico    │ ──▶ │  SHA3-256   │ ──▶ │ ML-DSA.Sign()   │
│                 │     │ (UTF-8 bytes)    │     │  (32 bytes) │     │ (3,309 bytes)   │
└─────────────────┘     └──────────────────┘     └─────────────┘     └─────────────────┘
                                                                              │
                                                                              ▼
                                                                     ┌─────────────────┐
                                                                     │  Certificado    │
                                                                     │  TBS + σ        │
                                                                     └─────────────────┘
```

---

## Proceso de Verificación de Certificados

Cuando un cliente recibe un certificado, ejecuta las siguientes validaciones:

### Paso 1: Verificar Presencia de Firma
```
if certificado.signatureValue == null:
    RECHAZAR → "Certificado sin firma"
```

### Paso 2: Verificar Emisor (Issuer)
```
if certificado.issuer ≠ trust_anchor.subject:
    RECHAZAR → "Issuer no coincide con CA de confianza"
```

### Paso 3: Verificar Firma Criptográfica

Se reconstruye el hash y se verifica contra la firma:
```
tbs_bytes = canonicalize(certificado.TBS)
hash = SHA3-256(tbs_bytes)
valid = ML-DSA.Verify(pk_CA, hash, certificado.signatureValue)

if not valid:
    RECHAZAR → "Firma inválida"
```

### Paso 4: Verificar Período de Validez
```
if tiempo_actual < certificado.validity.notBefore:
    RECHAZAR → "Certificado aún no válido"

if tiempo_actual > certificado.validity.notAfter:
    RECHAZAR → "Certificado expirado"
```

### Paso 5: Aceptar Certificado

Si todas las verificaciones pasan, el certificado es válido.

### Diagrama del Proceso
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        VERIFICACIÓN DE CERTIFICADO                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                         ┌────────────────────────┐
                         │  ¿Tiene firma?         │
                         └───────────┬────────────┘
                                     │
                          No ────────┼──────── Sí
                           │         │          │
                           ▼         │          ▼
                    ┌──────────┐     │   ┌────────────────────────┐
                    │ RECHAZAR │     │   │ ¿Issuer = Trust Anchor?│
                    └──────────┘     │   └───────────┬────────────┘
                                     │               │
                                     │    No ────────┼──────── Sí
                                     │     │         │          │
                                     │     ▼         │          ▼
                                     │ ┌──────────┐  │   ┌────────────────────────┐
                                     │ │ RECHAZAR │  │   │ Reconstruir TBS        │
                                     │ └──────────┘  │   │ hash = SHA3-256(TBS)   │
                                     │               │   │ ¿Verify(pk, hash, σ)?  │
                                     │               │   └───────────┬────────────┘
                                     │               │               │
                                     │               │    No ────────┼──────── Sí
                                     │               │     │         │          │
                                     │               │     ▼         │          ▼
                                     │               │ ┌──────────┐  │   ┌────────────────────────┐
                                     │               │ │ RECHAZAR │  │   │ ¿notBefore ≤ t ≤       │
                                     │               │ └──────────┘  │   │        notAfter?       │
                                     │               │               │   └───────────┬────────────┘
                                     │               │               │               │
                                     │               │               │    No ────────┼──────── Sí
                                     │               │               │     │         │          │
                                     │               │               │     ▼         │          ▼
                                     │               │               │ ┌──────────┐  │   ┌──────────┐
                                     │               │               │ │ RECHAZAR │  │   │ ACEPTAR  │
                                     │               │               │ └──────────┘  │   └──────────┘
```

---

## Formato de Certificado

Perfil JSON simplificado inspirado en X.509:
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

## Cobertura de Tests

| Categoría | Tests | Descripción |
|-----------|-------|-------------|
| Certificados válidos | 6 | Raíz, entidad final, cadena, condiciones límite |
| Certificados inválidos | 8 | Expirado, manipulado, issuer incorrecto, sin firma |
| Verificación de cadena | 2 | Raíz inválido, raíz no autofirmado |
```bash
$ pytest tests/ -v
========================= 16 passed in 2.81s =========================
```

## Limitaciones

- Jerarquía de un solo nivel (sin CAs intermedias)
- Sin mecanismo de revocación (CRL/OCSP)
- Serialización JSON (no ASN.1 DER)
- Sin integración TLS

## Referencias

- [NIST FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [dilithium-py](https://github.com/GiacomoPope/dilithium-py)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)