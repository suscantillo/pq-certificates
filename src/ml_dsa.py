from hashlib import sha3_256
from dilithium_py.ml_dsa import ML_DSA_65


def compute_sha3_256(data: bytes) -> bytes:
    return sha3_256(data).digest()


class MLDSAWrapper:
    PK_SIZE = 1952
    SK_SIZE = 4032
    SIG_SIZE = 3309
    HASH_SIZE = 32
    ALGORITHM = "ML-DSA-65"
    
    @staticmethod
    def keygen() -> tuple[bytes, bytes]:

        pk, sk = ML_DSA_65.keygen()
        return pk, sk
    
    @staticmethod
    def sign(secret_key: bytes, message: bytes) -> bytes:

        if len(secret_key) != MLDSAWrapper.SK_SIZE:
            raise ValueError(
                f"Secret key debe ser {MLDSAWrapper.SK_SIZE} bytes, "
                f"recibido {len(secret_key)}"
            )
        
      
        message_hash = compute_sha3_256(message)
        return ML_DSA_65.sign(secret_key, message_hash)
    
    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    
        if len(public_key) != MLDSAWrapper.PK_SIZE:
            return False
        
        if len(signature) != MLDSAWrapper.SIG_SIZE:
            return False
        
        try:
            
            message_hash = compute_sha3_256(message)
            return ML_DSA_65.verify(public_key, message_hash, signature)
        except Exception:
            return False


mldsa = MLDSAWrapper()