import logging
import os
import sys
import tempfile
import zipfile
import json
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from kysider_compression import compress_file_blocks
from kysider_keys import (
    RECIPIENT_KEY_METHODS,
    load_recipient_public_key,
    password_wrap_context,
    wrap_password_key,
    wrap_recipient_key,
)
from kysider_security import (
    CIPHER_METHODS,
    CHUNK_SIZE,
    COMPRESSION_BLOCK_SIZE,
    KEY_WRAPPING_METHODS,
    MAX_CONTAINER_BYTES,
    MAX_PAYLOAD_BYTES,
    MAX_ZIP_MEMBERS,
    chunk_associated_data,
    chunk_nonce,
    derive_container_key,
    encrypt_payload,
    generate_hardware_fingerprint,
    iter_fixed_chunks,
    process_chunks_in_parallel,
)


logger = logging.getLogger("kysider.packager")


class KYSiderPackager:
    def __init__(self, container_name: str, encryption_method: str = "AES-256-GCM"):
        if not container_name.lower().endswith(".kysd"):
            self.container_name = container_name + ".kysd"
        else:
            self.container_name = container_name

        if encryption_method not in CIPHER_METHODS:
            raise ValueError("Unsupported encryption method.")
        self.maker_hwid = generate_hardware_fingerprint()
        self.bound_id = secrets.token_urlsafe(32)
        self.enc_id = secrets.token_urlsafe(32)
        self.encryption_method = encryption_method

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a secure cryptographic key using PBKDF2-HMAC-SHA256 (600,000 iterations)."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        return kdf.derive(password.encode())

    @staticmethod
    def _path_is_within(path: str, root: str) -> bool:
        try:
            common_path = os.path.commonpath((path, root))
        except ValueError:
            return False
        return os.path.normcase(common_path) == os.path.normcase(root)

    @classmethod
    def _payload_temp_parent(cls, source_path: str) -> str:
        if not os.path.isdir(source_path):
            return tempfile.gettempdir()
        source_root = os.path.realpath(source_path)
        candidates = (
            tempfile.gettempdir(),
            os.path.dirname(source_root),
            os.environ.get("LOCALAPPDATA", ""),
            os.path.expanduser("~"),
        )
        fallback = None
        for candidate in candidates:
            if not candidate or not os.path.isdir(candidate) or not os.access(candidate, os.W_OK):
                continue
            real_candidate = os.path.realpath(candidate)
            fallback = fallback or real_candidate
            if not cls._path_is_within(real_candidate, source_root):
                return real_candidate
        if fallback:
            return fallback
        raise OSError("No writable temporary directory is available.")

    def create_container(
        self,
        source_path: str,
        password: str,
        overwrite: bool = False,
        key_wrapping_method: str = "Password + EncID only",
        recipient_public_key_path: str = "",
    ):
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Source path '{source_path}' does not exist.")
        if os.path.islink(source_path):
            raise ValueError("Symbolic-link sources are not supported.")
        if not password:
            raise ValueError("Password cannot be empty.")
        if key_wrapping_method not in KEY_WRAPPING_METHODS:
            raise ValueError("Unsupported recipient key wrapping method.")
        if key_wrapping_method in RECIPIENT_KEY_METHODS and not recipient_public_key_path:
            raise ValueError("A recipient public key is required for this key wrapping method.")

        source_path = os.path.abspath(source_path)
        destination_path = os.path.abspath(self.container_name)
        destination_real_path = os.path.realpath(destination_path)
        destination_directory = os.path.dirname(destination_path)
        os.makedirs(destination_directory, exist_ok=True)
        if os.path.lexists(destination_path) and not overwrite:
            raise FileExistsError(f"Container '{destination_path}' already exists.")

        temporary_parent = self._payload_temp_parent(source_path)
        with tempfile.TemporaryDirectory(prefix="kysider-pack-", dir=temporary_parent) as temporary_directory:
            payload_path = os.path.join(temporary_directory, "payload.zip")
            compressed_path = os.path.join(temporary_directory, "payload.blocks")
            temporary_root = os.path.realpath(temporary_directory)
            total_source_bytes = 0
            entry_count = 0
            with zipfile.ZipFile(payload_path, "w", zipfile.ZIP_STORED) as payload_zip:
                if os.path.isdir(source_path):
                    source_root = os.path.realpath(source_path)
                    for root, directories, files in os.walk(source_root, followlinks=False):
                        directories[:] = [
                            directory for directory in directories
                            if not os.path.islink(os.path.join(root, directory))
                            and not self._path_is_within(
                                os.path.realpath(os.path.join(root, directory)),
                                temporary_root,
                            )
                        ]
                        for filename in files:
                            file_path = os.path.join(root, filename)
                            real_file_path = os.path.realpath(file_path)
                            if (
                                os.path.islink(file_path)
                                or real_file_path == destination_real_path
                                or self._path_is_within(real_file_path, temporary_root)
                            ):
                                continue
                            if not self._path_is_within(real_file_path, source_root):
                                continue
                            total_source_bytes += os.path.getsize(file_path)
                            entry_count += 1
                            if total_source_bytes > MAX_PAYLOAD_BYTES:
                                raise ValueError("Source archive exceeds the configured 1 GiB payload limit.")
                            if entry_count > MAX_ZIP_MEMBERS:
                                raise ValueError("Source folder contains too many files.")
                            archive_name = os.path.relpath(file_path, source_root).replace(os.sep, "/")
                            payload_zip.write(file_path, archive_name)
                else:
                    if not os.path.isfile(source_path):
                        raise ValueError("Source must be a regular file or directory.")
                    total_source_bytes = os.path.getsize(source_path)
                    if total_source_bytes > MAX_PAYLOAD_BYTES:
                        raise ValueError("Source file exceeds the configured 1 GiB payload limit.")
                    payload_zip.write(source_path, os.path.basename(source_path))

            uncompressed_size = os.path.getsize(payload_path)
            if uncompressed_size > MAX_PAYLOAD_BYTES:
                raise ValueError("Source archive exceeds the configured 1 GiB payload limit.")
            uncompressed_size, compressed_size, compression_block_count = compress_file_blocks(
                payload_path,
                compressed_path,
            )
            chunk_count = (compressed_size + CHUNK_SIZE - 1) // CHUNK_SIZE

            salt = secrets.token_bytes(16)
            nonce = secrets.token_bytes(12)
            metadata = {
                "format_version": 4 if key_wrapping_method == "Password + EncID only" else 5,
                "bound_id": self.bound_id,
                "compression": "deflate-blocks-v1",
                "encryption": self.encryption_method,
                "salt": salt.hex(),
                "nonce": nonce.hex(),
                "chunk_size": CHUNK_SIZE,
                "chunk_count": chunk_count,
                "compressed_size": compressed_size,
                "compression_block_size": COMPRESSION_BLOCK_SIZE,
                "compression_block_count": compression_block_count,
                "uncompressed_size": uncompressed_size,
            }
            if metadata["format_version"] == 4:
                metadata["maker_hwid"] = self.maker_hwid
                content_key = derive_container_key(password, self.enc_id, salt)
            else:
                recipient_public_key, recipient_id = load_recipient_public_key(
                    recipient_public_key_path,
                    key_wrapping_method,
                )
                content_key = secrets.token_bytes(32)
                wrap_context = password_wrap_context(key_wrapping_method, recipient_id)
                password_nonce, password_wrapped_key = wrap_password_key(
                    content_key,
                    password,
                    self.enc_id,
                    salt,
                    wrap_context,
                )
                metadata.update({
                    "key_wrapping": key_wrapping_method,
                    "recipient_key_id": recipient_id,
                    "recipient_wrapped_key": wrap_recipient_key(
                        key_wrapping_method,
                        recipient_public_key,
                        recipient_id,
                        content_key,
                        salt,
                    ),
                    "password_wrap_nonce": password_nonce,
                    "password_wrapped_key": password_wrapped_key,
                })

            def encrypt_chunk(index: int, chunk: bytes) -> bytes:
                return encrypt_payload(
                    self.encryption_method,
                    content_key,
                    chunk_nonce(nonce, index),
                    chunk,
                    chunk_associated_data(metadata, index),
                )

            temp_descriptor, temporary_container = tempfile.mkstemp(
                prefix=".kysider-",
                suffix=".tmp",
                dir=destination_directory,
            )
            os.close(temp_descriptor)
            try:
                with zipfile.ZipFile(temporary_container, "w", zipfile.ZIP_STORED) as container:
                    container.writestr("metadata.json", json.dumps(metadata, sort_keys=True, separators=(",", ":")))
                    with container.open("payload.enc", "w", force_zip64=True) as encrypted_member:
                        with open(compressed_path, "rb") as compressed_file:
                            encrypted_count = process_chunks_in_parallel(
                                iter_fixed_chunks(compressed_file, CHUNK_SIZE, chunk_count),
                                encrypted_member,
                                encrypt_chunk,
                            )
                    if encrypted_count != chunk_count:
                        raise ValueError("Encrypted chunk count did not match the compressed payload.")
                if os.path.getsize(temporary_container) > MAX_CONTAINER_BYTES:
                    raise ValueError("Container exceeds the configured size limit.")
                if overwrite:
                    os.replace(temporary_container, destination_path)
                else:
                    os.link(temporary_container, destination_path)
                    os.unlink(temporary_container)
            finally:
                if os.path.exists(temporary_container):
                    os.remove(temporary_container)
                del content_key
        self.container_name = destination_path

        logger.info("Created container %s using %s.", self.container_name, self.encryption_method)

if __name__ == "__main__":
    from kysider_gui import main

    sys.exit(main())