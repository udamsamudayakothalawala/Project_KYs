import hashlib
import json
import os
import platform
import re
import subprocess
from pathlib import Path
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from itertools import chain
from typing import BinaryIO, Callable, Iterable
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


MAX_CONTAINER_BYTES = 2 * 1024 * 1024 * 1024
MAX_PAYLOAD_BYTES = 1024 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_ZIP_MEMBERS = 10_000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_EXPANSION_RATIO = 1000
CIPHER_METHODS = ("AES-256-GCM", "ChaCha20-Poly1305")
RECIPIENT_KEY_METHODS = ("RSA-4096", "ECC P-384", "ML-KEM-768", "ML-KEM-1024")
KEY_WRAPPING_METHODS = ("Password + EncID only",) + RECIPIENT_KEY_METHODS
CHUNK_SIZE = 1024 * 1024
COMPRESSION_BLOCK_SIZE = 1024 * 1024
SUSPICIOUS_EXTENSIONS = frozenset({
    ".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".jar", ".js", ".jse",
    ".lnk", ".msi", ".ps1", ".scr", ".vbe", ".vbs", ".wsf",
})


def suspicious_file_reasons(path: str) -> list[str]:
    suffix = Path(path).suffix.lower()
    if suffix in SUSPICIOUS_EXTENSIONS:
        return ["Executable, script, installer, or shortcut file type"]
    return []


def inspect_source_path(source_path: str, result_limit: int = 50) -> tuple[list[str], int]:
    suspicious_paths = []
    suspicious_count = 0

    def record(path: str):
        nonlocal suspicious_count
        if not suspicious_file_reasons(path):
            return
        suspicious_count += 1
        if len(suspicious_paths) < result_limit:
            suspicious_paths.append(path)

    if os.path.isdir(source_path):
        for root, directories, files in os.walk(source_path, followlinks=False):
            directories[:] = [
                directory for directory in directories
                if not os.path.islink(os.path.join(root, directory))
            ]
            for filename in files:
                file_path = os.path.join(root, filename)
                if not os.path.islink(file_path):
                    record(os.path.relpath(file_path, source_path))
    else:
        record(os.path.basename(source_path))

    return suspicious_paths, suspicious_count


def format_container_security_report(metadata: dict, container_size: int) -> str:
    version = metadata["format_version"]
    lines = [
        f"Container size: {container_size:,} bytes",
        f"Format version: {version}",
        f"Encryption: {metadata.get('encryption', 'AES-256-GCM (legacy format)')}",
        f"Hardware binding: {'enabled' if version in (2, 3, 4) else 'legacy binding'}",
        f"EncID required: {'yes' if version in (3, 4, 5) else 'no'}",
        f"Authenticated container data: {'yes' if version in (2, 3, 4) else 'legacy format; limited authentication'}",
    ]
    if version == 5:
        lines[3] = "Hardware binding: disabled for recipient portability"
        lines[5] = "Authenticated container data: yes"
        lines.append(f"Recipient key wrapping: {metadata['key_wrapping']}")
    if version in (4, 5):
        lines.append(f"Payload processed in parallel chunks: {metadata['chunk_count']:,}")
    lines.extend((
        "",
        "This report checks container metadata only. It does not scan encrypted contents for malware.",
    ))
    return "\n".join(lines)


def process_chunks_in_parallel(
    chunks: Iterable[bytes],
    output_file: BinaryIO,
    processor: Callable[[int, bytes], bytes],
) -> int:
    chunk_iterator = iter(chunks)
    first_chunk = next(chunk_iterator, None)
    if first_chunk is None:
        return 0
    second_chunk = next(chunk_iterator, None)
    if second_chunk is None:
        output_file.write(processor(0, first_chunk))
        return 1

    worker_count = min(8, os.cpu_count() or 1)
    pending_limit = worker_count * 2
    pending = deque()
    chunk_count = 0

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="kysider") as executor:
        for index, chunk in enumerate(chain((first_chunk, second_chunk), chunk_iterator)):
            pending.append(executor.submit(processor, index, chunk))
            chunk_count += 1
            if len(pending) >= pending_limit:
                output_file.write(pending.popleft().result())

        while pending:
            output_file.write(pending.popleft().result())

    return chunk_count


def iter_fixed_chunks(source_file: BinaryIO, chunk_size: int, chunk_count: int):
    for _ in range(chunk_count):
        chunk = source_file.read(chunk_size)
        if not chunk:
            raise ValueError("Stream ended before all declared chunks were read.")
        yield chunk
    if source_file.read(1):
        raise ValueError("Stream contains bytes after its declared chunks.")


def chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    if len(base_nonce) != 12 or index < 0 or index >= 2**64:
        raise ValueError("Chunk nonce parameters are invalid.")
    return base_nonce[:4] + index.to_bytes(8, "big")


def chunk_associated_data(metadata: dict, index: int) -> bytes:
    return metadata_associated_data(metadata) + index.to_bytes(8, "big")


def metadata_associated_data(metadata: dict) -> bytes:
    return json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _is_hex(value, expected_bytes=None):
    if not isinstance(value, str) or len(value) % 2:
        return False
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        return False
    return expected_bytes is None or len(decoded) == expected_bytes


def derive_container_key(password: str, enc_id: str, salt: bytes) -> bytes:
    key_material = password.encode("utf-8") + b"\x00" + enc_id.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(key_material)


def encrypt_payload(method: str, key: bytes, nonce: bytes, payload: bytes, associated_data: bytes) -> bytes:
    if method == "AES-256-GCM":
        return AESGCM(key).encrypt(nonce, payload, associated_data)
    if method == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key).encrypt(nonce, payload, associated_data)
    raise ValueError("Unsupported authenticated encryption method.")


def decrypt_payload(method: str, key: bytes, nonce: bytes, payload: bytes, associated_data: bytes) -> bytes:
    if method == "AES-256-GCM":
        return AESGCM(key).decrypt(nonce, payload, associated_data)
    if method == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key).decrypt(nonce, payload, associated_data)
    raise ValueError("Unsupported authenticated encryption method.")


def validate_metadata(metadata: dict) -> int:
    if not isinstance(metadata, dict):
        raise ValueError("Container metadata must be a JSON object.")

    version = metadata.get("format_version", 1)
    if type(version) is not int or version not in (1, 2, 3, 4, 5):
        raise ValueError("Container metadata version is unsupported.")
    if version in (2, 3, 4, 5):
        required = ("maker_hwid", "bound_id", "compression", "salt", "nonce")
        if version in (3, 4, 5):
            required += ("encryption",)
        if version in (4, 5):
            required = tuple(field for field in required if field != "maker_hwid")
            required += (
                "chunk_size",
                "chunk_count",
                "compressed_size",
                "compression_block_size",
                "compression_block_count",
                "uncompressed_size",
            )
        if version == 5:
            required += (
                "key_wrapping",
                "recipient_key_id",
                "recipient_wrapped_key",
                "password_wrap_nonce",
                "password_wrapped_key",
            )
        if any(field not in metadata for field in required):
            raise ValueError("Container metadata is missing required fields.")
        if version in (2, 3, 4) and (
            not isinstance(metadata["maker_hwid"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", metadata["maker_hwid"])
        ):
            raise ValueError("Container hardware identifier is malformed.")
        if not isinstance(metadata["bound_id"], str) or len(metadata["bound_id"]) < 32 or len(metadata["bound_id"]) > 128:
            raise ValueError("Container recovery token is malformed.")
        expected_compression = "deflate-blocks-v1" if version in (4, 5) else "deflate-lz77-huffman-v1"
        if metadata["compression"] != expected_compression:
            raise ValueError("Container compression method is unsupported.")
        if version in (3, 4, 5) and metadata["encryption"] not in CIPHER_METHODS:
            raise ValueError("Container encryption method is unsupported.")
        if not _is_hex(metadata["salt"], 16) or not _is_hex(metadata["nonce"], 12):
            raise ValueError("Container cryptographic parameters are malformed.")
        if version in (4, 5):
            integer_fields = (
                "chunk_size",
                "chunk_count",
                "compressed_size",
                "compression_block_size",
                "compression_block_count",
                "uncompressed_size",
            )
            if any(type(metadata[field]) is not int or metadata[field] <= 0 for field in integer_fields):
                raise ValueError("Container stream parameters are malformed.")
            if (
                metadata["chunk_size"] != CHUNK_SIZE
                or metadata["compression_block_size"] != COMPRESSION_BLOCK_SIZE
                or metadata["compressed_size"] > MAX_CONTAINER_BYTES
                or metadata["uncompressed_size"] > MAX_PAYLOAD_BYTES
                or metadata["chunk_count"] != (metadata["compressed_size"] + CHUNK_SIZE - 1) // CHUNK_SIZE
                or metadata["compression_block_count"]
                != (metadata["uncompressed_size"] + COMPRESSION_BLOCK_SIZE - 1) // COMPRESSION_BLOCK_SIZE
            ):
                raise ValueError("Container stream parameters are inconsistent or exceed their limits.")
        if version == 5:
            algorithm = metadata["key_wrapping"]
            recipient_key_id = metadata["recipient_key_id"]
            wrapped_key = metadata["recipient_wrapped_key"]
            if algorithm not in RECIPIENT_KEY_METHODS:
                raise ValueError("Container recipient key method is unsupported.")
            if not isinstance(recipient_key_id, str) or not re.fullmatch(r"[0-9a-f]{64}", recipient_key_id):
                raise ValueError("Container recipient key identifier is malformed.")
            if not _is_hex(metadata["password_wrap_nonce"], 12) or not isinstance(metadata["password_wrapped_key"], str):
                raise ValueError("Password-wrapped key metadata is malformed.")
            if len(metadata["password_wrapped_key"]) > 256:
                raise ValueError("Password-wrapped key metadata exceeds its size limit.")
            if not isinstance(wrapped_key, dict):
                raise ValueError("Recipient-wrapped key metadata is malformed.")
            expected_fields = {
                "RSA-4096": {"wrapped_key"},
                "ECC P-384": {"ephemeral_public_key", "nonce", "wrapped_key"},
                "ML-KEM-768": {"encapsulation", "nonce", "wrapped_key"},
                "ML-KEM-1024": {"encapsulation", "nonce", "wrapped_key"},
            }[algorithm]
            if set(wrapped_key) != expected_fields:
                raise ValueError("Recipient-wrapped key metadata is malformed.")
            if any(not isinstance(value, str) or len(value) > 16 * 1024 for value in wrapped_key.values()):
                raise ValueError("Recipient-wrapped key metadata exceeds its size limit.")
            if algorithm != "RSA-4096" and not _is_hex(wrapped_key.get("nonce"), 12):
                raise ValueError("Recipient-wrapped key nonce is malformed.")
        if "password_hash" in metadata:
            raise ValueError("Authenticated metadata must not contain a password verifier.")
        return version

    legacy_required = ("maker_hwid", "password_hash", "bound_id", "salt", "nonce")
    if any(field not in metadata for field in legacy_required):
        raise ValueError("Legacy container metadata is missing required fields.")
    if not isinstance(metadata["maker_hwid"], str) or not re.fullmatch(r"[0-9a-fA-F]{64}", metadata["maker_hwid"]):
        raise ValueError("Legacy hardware identifier is malformed.")
    if not isinstance(metadata["password_hash"], str) or not re.fullmatch(r"[0-9a-fA-F]{64}", metadata["password_hash"]):
        raise ValueError("Legacy password verifier is malformed.")
    if not isinstance(metadata["bound_id"], str) or not metadata["bound_id"]:
        raise ValueError("Legacy recovery token is malformed.")
    if not _is_hex(metadata["salt"], 16) or not _is_hex(metadata["nonce"], 12):
        raise ValueError("Legacy cryptographic parameters are malformed.")
    compression = metadata.get("compression")
    if compression not in (None, "lz77-lzss-huffman-v1", "deflate-lz77-huffman-v1"):
        raise ValueError("Legacy container compression method is unsupported.")
    return 1


def generate_hardware_fingerprint() -> str:
    system = platform.system()
    identifier = None

    if system == "Windows":
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            identifier, _ = winreg.QueryValueEx(key, "MachineGuid")
    elif system == "Linux":
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id", "/sys/class/dmi/id/product_uuid"):
            try:
                with open(path, "r", encoding="ascii") as machine_file:
                    identifier = machine_file.read().strip()
                if identifier:
                    break
            except OSError:
                continue
    elif system == "Darwin":
        output = subprocess.check_output(
            ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
        match = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', output)
        if match:
            identifier = match.group(1)

    if not isinstance(identifier, str) or not identifier.strip():
        raise RuntimeError("A stable system identifier could not be read; hardware binding was not weakened.")
    return hashlib.sha256(f"{system}:{identifier.strip()}".encode("utf-8")).hexdigest()


def legacy_hardware_fingerprint() -> str:
    raw_hardware = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(
                ["wmic", "baseboard", "get", "serialnumber"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            raw_hardware += "-" + output.strip()
        elif platform.system() == "Linux":
            path = "/sys/class/dmi/id/product_uuid"
            if os.path.exists(path):
                with open(path, "r", encoding="ascii") as hardware_file:
                    raw_hardware += "-" + hardware_file.read().strip()
        elif platform.system() == "Darwin":
            output = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            for line in output.splitlines():
                if "IOPlatformUUID" in line:
                    raw_hardware += "-" + line.strip()
                    break
    except (OSError, subprocess.SubprocessError):
        pass
    return hashlib.sha256(raw_hardware.encode("utf-8")).hexdigest()