import base64
import hashlib
import json
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pqcrypto.kem import ml_kem_768, ml_kem_1024

from kysider_security import (
    RECIPIENT_KEY_METHODS,
    derive_container_key,
    metadata_associated_data,
)


KEY_FILE_LIMIT = 64 * 1024
_KEY_FILE_FORMAT = "kysider-recipient-key"
_KEY_FILE_VERSION = 1
_KEY_CONTEXT = b"KYSider recipient content-key wrap v1"


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise ValueError("Recipient key data is malformed.")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("Recipient key data is malformed.") from error


def _read_key_file(path: str) -> dict:
    if os.path.islink(path) or not os.path.isfile(path):
        raise FileNotFoundError("Recipient key file is missing or is a symbolic link.")
    if os.path.getsize(path) > KEY_FILE_LIMIT:
        raise ValueError("Recipient key file exceeds the size limit.")
    with open(path, "r", encoding="utf-8") as key_file:
        payload = json.load(key_file)
    if (
        not isinstance(payload, dict)
        or payload.get("format") != _KEY_FILE_FORMAT
        or payload.get("version") != _KEY_FILE_VERSION
        or payload.get("algorithm") not in RECIPIENT_KEY_METHODS
    ):
        raise ValueError("Unsupported or malformed KYSider recipient key file.")
    return payload


def generate_recipient_keypair(algorithm: str) -> tuple[bytes, bytes]:
    if algorithm == "RSA-4096":
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return public_bytes, private_bytes
    if algorithm == "ECC P-384":
        private_key = ec.generate_private_key(ec.SECP384R1())
        public_bytes = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_bytes = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return public_bytes, private_bytes
    kem = _kem_module(algorithm)
    public_bytes, private_bytes = kem.keygen()
    return bytes(public_bytes), bytes(private_bytes)


def _kem_module(algorithm: str):
    if algorithm == "ML-KEM-768":
        return ml_kem_768
    if algorithm == "ML-KEM-1024":
        return ml_kem_1024
    raise ValueError("Unsupported recipient key method.")


def save_recipient_public_key(path: str, algorithm: str, public_key: bytes):
    if algorithm not in RECIPIENT_KEY_METHODS:
        raise ValueError("Unsupported recipient key method.")
    payload = {
        "format": _KEY_FILE_FORMAT,
        "version": _KEY_FILE_VERSION,
        "key_type": "public",
        "algorithm": algorithm,
        "public_key": _encode(public_key),
        "public_key_id": recipient_key_id(algorithm, public_key),
    }
    _write_key_file(path, payload)


def save_recipient_private_key(path: str, algorithm: str, private_key: bytes, key_id: str, passphrase: str):
    if algorithm not in RECIPIENT_KEY_METHODS:
        raise ValueError("Unsupported recipient key method.")
    if not isinstance(passphrase, str) or len(passphrase) < 12:
        raise ValueError("Private-key passphrase must be at least 12 characters.")
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_private_key_protection_key(passphrase, salt)
    associated_data = _private_key_associated_data(algorithm)
    encrypted_private_key = AESGCM(key).encrypt(nonce, private_key, associated_data)
    payload = {
        "format": _KEY_FILE_FORMAT,
        "version": _KEY_FILE_VERSION,
        "key_type": "private",
        "algorithm": algorithm,
        "public_key_id": key_id,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "private_key": _encode(encrypted_private_key),
    }
    _write_key_file(path, payload)
    del key


def _write_key_file(path: str, payload: dict):
    encoded = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
    if len(encoded) > KEY_FILE_LIMIT:
        raise ValueError("Generated recipient key file exceeds the size limit.")
    if os.path.islink(path):
        raise ValueError("Recipient key path must not be a symbolic link.")
    temporary_path = f"{path}.kysider-tmp-{secrets.token_hex(8)}"
    try:
        with open(temporary_path, "xb") as key_file:
            key_file.write(encoded)
        os.replace(temporary_path, path)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)


def _private_key_associated_data(algorithm: str) -> bytes:
    return metadata_associated_data({
        "format": _KEY_FILE_FORMAT,
        "version": _KEY_FILE_VERSION,
        "key_type": "private",
        "algorithm": algorithm,
    })


def _derive_private_key_protection_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
    return kdf.derive(passphrase.encode("utf-8"))


def load_recipient_public_key(path: str, expected_algorithm: str) -> tuple[bytes, str]:
    payload = _read_key_file(path)
    if payload.get("key_type") != "public" or payload["algorithm"] != expected_algorithm:
        raise ValueError("Selected public key does not match the chosen recipient key method.")
    public_key = _decode(payload.get("public_key"))
    key_id = recipient_key_id(expected_algorithm, public_key)
    if payload.get("public_key_id") != key_id:
        raise ValueError("Recipient public key fingerprint is invalid.")
    if expected_algorithm == "RSA-4096":
        loaded_key = serialization.load_der_public_key(public_key)
        if not isinstance(loaded_key, rsa.RSAPublicKey) or loaded_key.key_size != 4096:
            raise ValueError("Recipient public key is not RSA-4096.")
    elif expected_algorithm == "ECC P-384":
        loaded_key = serialization.load_der_public_key(public_key)
        if not isinstance(loaded_key, ec.EllipticCurvePublicKey) or loaded_key.curve.name != "secp384r1":
            raise ValueError("Recipient public key is not ECC P-384.")
    else:
        kem = _kem_module(expected_algorithm)
        if len(public_key) != kem.PUBLIC_KEY_SIZE:
            raise ValueError("Recipient public key has an invalid size.")
    return public_key, key_id


def load_recipient_private_key(path: str, passphrase: str, expected_algorithm: str) -> tuple[bytes, str]:
    payload = _read_key_file(path)
    if payload.get("key_type") != "private" or payload["algorithm"] != expected_algorithm:
        raise ValueError("Selected private key does not match the container's recipient key method.")
    try:
        salt = bytes.fromhex(payload["salt"])
        nonce = bytes.fromhex(payload["nonce"])
        if len(salt) != 16 or len(nonce) != 12:
            raise ValueError("Private-key protection parameters are malformed.")
        protection_key = _derive_private_key_protection_key(passphrase, salt)
        private_key = AESGCM(protection_key).decrypt(
            nonce,
            _decode(payload.get("private_key")),
            _private_key_associated_data(expected_algorithm),
        )
    except (InvalidTag, KeyError, ValueError) as error:
        raise ValueError("Private key is malformed or its passphrase is incorrect.") from error
    finally:
        if "protection_key" in locals():
            del protection_key

    key_id = payload.get("public_key_id")
    if not isinstance(key_id, str) or len(key_id) != 64:
        raise ValueError("Private key file does not identify its matching public key.")
    return private_key, key_id


def recipient_key_id(algorithm: str, public_key: bytes) -> str:
    return hashlib.sha256(algorithm.encode("ascii") + b"\x00" + public_key).hexdigest()


def _recipient_wrap_context(algorithm: str, key_id: str) -> bytes:
    return metadata_associated_data({
        "format_version": 5,
        "key_wrapping": algorithm,
        "recipient_key_id": key_id,
    })


def password_wrap_context(algorithm: str, key_id: str) -> bytes:
    return _recipient_wrap_context(algorithm, key_id)


def _wrap_kem_shared_secret(shared_secret: bytes, salt: bytes, key_id: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_KEY_CONTEXT + bytes.fromhex(key_id),
    ).derive(shared_secret)


def wrap_recipient_key(
    algorithm: str,
    public_key: bytes,
    key_id: str,
    data_key: bytes,
    salt: bytes,
) -> dict:
    context = _recipient_wrap_context(algorithm, key_id)
    if algorithm == "RSA-4096":
        loaded_key = serialization.load_der_public_key(public_key)
        if not isinstance(loaded_key, rsa.RSAPublicKey) or loaded_key.key_size != 4096:
            raise ValueError("Recipient public key is not RSA-4096.")
        wrapped = loaded_key.encrypt(
            data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=context,
            ),
        )
        return {"wrapped_key": _encode(wrapped)}

    if algorithm == "ECC P-384":
        recipient_key = serialization.load_der_public_key(public_key)
        if not isinstance(recipient_key, ec.EllipticCurvePublicKey) or recipient_key.curve.name != "secp384r1":
            raise ValueError("Recipient public key is not ECC P-384.")
        ephemeral_key = ec.generate_private_key(ec.SECP384R1())
        shared_secret = ephemeral_key.exchange(ec.ECDH(), recipient_key)
        wrapping_key = _wrap_kem_shared_secret(shared_secret, salt, key_id)
        ephemeral_public = ephemeral_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        nonce = secrets.token_bytes(12)
        wrapped = AESGCM(wrapping_key).encrypt(nonce, data_key, context)
        return {
            "ephemeral_public_key": _encode(ephemeral_public),
            "nonce": nonce.hex(),
            "wrapped_key": _encode(wrapped),
        }

    kem = _kem_module(algorithm)
    ciphertext, shared_secret = kem.encaps(public_key)
    wrapping_key = _wrap_kem_shared_secret(shared_secret, salt, key_id)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(wrapping_key).encrypt(nonce, data_key, context)
    return {
        "encapsulation": _encode(bytes(ciphertext)),
        "nonce": nonce.hex(),
        "wrapped_key": _encode(wrapped),
    }


def unwrap_recipient_key(
    algorithm: str,
    private_key: bytes,
    key_id: str,
    wrapped_data: dict,
    salt: bytes,
) -> bytes:
    context = _recipient_wrap_context(algorithm, key_id)
    if not isinstance(wrapped_data, dict):
        raise ValueError("Wrapped recipient key metadata is malformed.")
    if algorithm == "RSA-4096":
        loaded_key = serialization.load_der_private_key(private_key, password=None)
        if not isinstance(loaded_key, rsa.RSAPrivateKey) or loaded_key.key_size != 4096:
            raise ValueError("Recipient private key is not RSA-4096.")
        return loaded_key.decrypt(
            _decode(wrapped_data.get("wrapped_key")),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=context,
            ),
        )
    if algorithm == "ECC P-384":
        recipient_key = serialization.load_der_private_key(private_key, password=None)
        if not isinstance(recipient_key, ec.EllipticCurvePrivateKey) or recipient_key.curve.name != "secp384r1":
            raise ValueError("Recipient private key is not ECC P-384.")
        ephemeral_key = serialization.load_der_public_key(_decode(wrapped_data.get("ephemeral_public_key")))
        if not isinstance(ephemeral_key, ec.EllipticCurvePublicKey) or ephemeral_key.curve.name != "secp384r1":
            raise ValueError("Ephemeral key is not ECC P-384.")
        shared_secret = recipient_key.exchange(ec.ECDH(), ephemeral_key)
    else:
        kem = _kem_module(algorithm)
        shared_secret = kem.decaps(private_key, _decode(wrapped_data.get("encapsulation")))

    wrapping_key = _wrap_kem_shared_secret(shared_secret, salt, key_id)
    nonce = bytes.fromhex(wrapped_data["nonce"])
    if len(nonce) != 12:
        raise ValueError("Recipient key wrapping nonce is malformed.")
    return AESGCM(wrapping_key).decrypt(
        nonce,
        _decode(wrapped_data.get("wrapped_key")),
        context,
    )


def wrap_password_key(data_key: bytes, password: str, enc_id: str, salt: bytes, context: bytes) -> tuple[str, str]:
    wrapping_key = derive_container_key(password, enc_id, salt)
    nonce = secrets.token_bytes(12)
    wrapped = AESGCM(wrapping_key).encrypt(nonce, data_key, context)
    del wrapping_key
    return nonce.hex(), _encode(wrapped)


def unwrap_password_key(
    wrapped_data_key: str,
    nonce_hex: str,
    password: str,
    enc_id: str,
    salt: bytes,
    context: bytes,
) -> bytes:
    wrapping_key = derive_container_key(password, enc_id, salt)
    try:
        nonce = bytes.fromhex(nonce_hex)
        if len(nonce) != 12:
            raise ValueError("Password key wrapping nonce is malformed.")
        return AESGCM(wrapping_key).decrypt(nonce, _decode(wrapped_data_key), context)
    finally:
        del wrapping_key
