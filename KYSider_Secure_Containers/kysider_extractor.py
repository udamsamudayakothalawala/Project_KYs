import hashlib
import hmac
import io
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import PurePosixPath, PureWindowsPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from kysider_compression import decompress_file_blocks, decompress_payload
from kysider_keys import (
    RECIPIENT_KEY_METHODS,
    load_recipient_private_key,
    password_wrap_context,
    unwrap_password_key,
    unwrap_recipient_key,
)
from kysider_security import (
    MAX_CONTAINER_BYTES,
    MAX_EXTRACTED_BYTES,
    MAX_EXPANSION_RATIO,
    MAX_MEMBER_BYTES,
    MAX_METADATA_BYTES,
    MAX_PAYLOAD_BYTES,
    MAX_ZIP_MEMBERS,
    decrypt_payload,
    chunk_associated_data,
    chunk_nonce,
    derive_container_key,
    generate_hardware_fingerprint,
    legacy_hardware_fingerprint,
    metadata_associated_data,
    process_chunks_in_parallel,
    suspicious_file_reasons,
    validate_metadata,
)


logger = logging.getLogger("kysider.extractor")


class KYSiderExtractor:
    def __init__(self, container_path: str):
        self.container_path = os.path.realpath(os.path.abspath(container_path))
        self.container_basename = os.path.splitext(os.path.basename(container_path))[0]
        self.recovery_record_path = None
        self.shard_paths = []
        self.failed_unlock_attempts = 0
        self.last_failure = None
        self.suspicious_files = []
        self.metadata = self._load_metadata()
        self.format_version = validate_metadata(self.metadata)

    @staticmethod
    def _read_metadata(container_path: str) -> dict:
        if not os.path.isfile(container_path) or os.path.islink(container_path):
            raise FileNotFoundError(f"Container '{container_path}' is unavailable or is a symbolic link.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(container_path, flags)
        with os.fdopen(descriptor, "rb") as container_file:
            if os.fstat(container_file.fileno()).st_size > MAX_CONTAINER_BYTES:
                raise ValueError("Container exceeds the configured size limit.")
            with zipfile.ZipFile(container_file, "r") as container:
                infos = container.infolist()
                names = [info.filename for info in infos]
                if len(names) != 2 or set(names) != {"metadata.json", "payload.enc"}:
                    raise ValueError("Invalid KYSider container structure.")
                metadata_info = container.getinfo("metadata.json")
                if metadata_info.file_size > MAX_METADATA_BYTES:
                    raise ValueError("Container metadata exceeds the configured size limit.")
                metadata = json.loads(container.read(metadata_info).decode("utf-8"))
        validate_metadata(metadata)
        return metadata

    def _load_metadata(self) -> dict:
        return self._read_metadata(self.container_path)

    def _derive_key(self, password: str, salt: bytes, enc_id: str = "") -> bytes:
        if self.format_version in (3, 4, 5):
            return derive_container_key(password, enc_id, salt)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600_000,
        )
        return kdf.derive(password.encode("utf-8"))

    def _read_encrypted_payload(self) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.container_path, flags)
        with os.fdopen(descriptor, "rb") as container_file:
            with zipfile.ZipFile(container_file, "r") as container:
                payload_info = container.getinfo("payload.enc")
                if payload_info.file_size > MAX_PAYLOAD_BYTES + 1024:
                    raise ValueError("Encrypted payload exceeds the configured size limit.")
                if payload_info.file_size and payload_info.file_size / max(payload_info.compress_size, 1) > MAX_EXPANSION_RATIO:
                    raise ValueError("Encrypted payload exceeds the expansion-ratio limit.")
                return container.read(payload_info)

    def _record_unlock_failure(self, reason: str):
        self.failed_unlock_attempts += 1
        self.last_failure = reason
        if self.failed_unlock_attempts < 3 or self.format_version not in (2, 3, 4, 5):
            return
        try:
            self.recovery_record_path = self.scatter_container()
            self.last_failure = "chunkhide_started"
        except (OSError, ValueError) as error:
            self.last_failure = "chunkhide_failed"
            logger.error("Recovery set creation failed; original container was left in place: %s", error)

    @staticmethod
    def _iter_encrypted_chunks(source_file, chunk_size: int, chunk_count: int, compressed_size: int):
        remaining = compressed_size
        for _ in range(chunk_count):
            plaintext_size = min(chunk_size, remaining)
            encrypted_chunk = source_file.read(plaintext_size + 16)
            if len(encrypted_chunk) != plaintext_size + 16:
                raise ValueError("Encrypted chunk stream is truncated.")
            remaining -= plaintext_size
            yield encrypted_chunk
        if remaining or source_file.read(1):
            raise ValueError("Encrypted chunk stream does not match its metadata.")

    def _decrypt_v4_payload(self, derived_key: bytes, destination_path: str):
        metadata = self.metadata
        expected_ciphertext_size = metadata["compressed_size"] + metadata["chunk_count"] * 16
        with zipfile.ZipFile(self.container_path, "r") as container:
            payload_info = container.getinfo("payload.enc")
            if payload_info.file_size != expected_ciphertext_size:
                raise ValueError("Encrypted payload size does not match its metadata.")
            nonce = bytes.fromhex(metadata["nonce"])

            def decrypt_chunk(index: int, chunk: bytes) -> bytes:
                return decrypt_payload(
                    metadata["encryption"],
                    derived_key,
                    chunk_nonce(nonce, index),
                    chunk,
                    chunk_associated_data(metadata, index),
                )

            with container.open(payload_info, "r") as encrypted_file, open(destination_path, "wb") as output_file:
                decrypted_count = process_chunks_in_parallel(
                    self._iter_encrypted_chunks(
                        encrypted_file,
                        metadata["chunk_size"],
                        metadata["chunk_count"],
                        metadata["compressed_size"],
                    ),
                    output_file,
                    decrypt_chunk,
                )
        if decrypted_count != metadata["chunk_count"] or os.path.getsize(destination_path) != metadata["compressed_size"]:
            raise ValueError("Decrypted payload size does not match its metadata.")

    def unlock(
        self,
        provided_password: str,
        provided_enc_id: str = "",
        extract_to: str = "./extracted_payload",
        recipient_private_key_path: str = "",
        recipient_key_passphrase: str = "",
    ) -> bool:
        self.last_failure = None
        if not isinstance(provided_password, str) or not provided_password:
            self._record_unlock_failure("blank_password")
            logger.warning("Unlock failed because the password is empty.")
            return False

        if self.format_version in (3, 4, 5) and (not isinstance(provided_enc_id, str) or not provided_enc_id.strip()):
            self._record_unlock_failure("blank_enc_id")
            logger.warning("Unlock failed because EncID is empty.")
            return False

        if self.format_version != 5:
            try:
                current_hwid = (
                    generate_hardware_fingerprint()
                    if self.format_version in (2, 3, 4)
                    else legacy_hardware_fingerprint()
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                self.last_failure = "hardware_check"
                logger.error("Unlock failed because this system could not be verified: %s", error)
                return False

            if not hmac.compare_digest(current_hwid, self.metadata["maker_hwid"]):
                self.last_failure = "hardware_mismatch"
                logger.warning("Unlock failed because the container is bound to a different system.")
                return False

        salt = bytes.fromhex(self.metadata["salt"])
        nonce = bytes.fromhex(self.metadata["nonce"])
        if self.format_version == 1:
            password_hash = hashlib.sha256(provided_password.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(password_hash, self.metadata["password_hash"].lower()):
                self._record_unlock_failure("password")
                logger.warning("Unlock failed because the password was incorrect.")
                return False

        derived_key = (
            b""
            if self.format_version == 5
            else self._derive_key(provided_password, salt, provided_enc_id.strip())
        )
        try:
            if self.format_version in (4, 5):
                with tempfile.TemporaryDirectory(prefix="kysider-unlock-") as temporary_directory:
                    compressed_path = os.path.join(temporary_directory, "payload.blocks")
                    payload_path = os.path.join(temporary_directory, "payload.zip")
                    if self.format_version == 5:
                        key_method = self.metadata["key_wrapping"]
                        if key_method not in RECIPIENT_KEY_METHODS:
                            raise ValueError("Container recipient key method is unsupported.")
                        if not recipient_private_key_path or not recipient_key_passphrase:
                            raise ValueError("Recipient private key and its passphrase are required.")
                        wrap_context = password_wrap_context(
                            key_method,
                            self.metadata["recipient_key_id"],
                        )
                        password_data_key = unwrap_password_key(
                            self.metadata["password_wrapped_key"],
                            self.metadata["password_wrap_nonce"],
                            provided_password,
                            provided_enc_id.strip(),
                            salt,
                            wrap_context,
                        )
                        private_key, private_key_id = load_recipient_private_key(
                            recipient_private_key_path,
                            recipient_key_passphrase,
                            key_method,
                        )
                        if not hmac.compare_digest(private_key_id, self.metadata["recipient_key_id"]):
                            raise ValueError("Recipient private key does not match this container.")
                        recipient_data_key = unwrap_recipient_key(
                            key_method,
                            private_key,
                            private_key_id,
                            self.metadata["recipient_wrapped_key"],
                            salt,
                        )
                        if not hmac.compare_digest(password_data_key, recipient_data_key):
                            raise InvalidTag
                        content_key = password_data_key
                        del recipient_data_key
                        del private_key
                    else:
                        content_key = derived_key
                    self._decrypt_v4_payload(content_key, compressed_path)
                    decompress_file_blocks(
                        compressed_path,
                        payload_path,
                        self.metadata["compression_block_count"],
                        self.metadata["uncompressed_size"],
                    )
                    self.suspicious_files = self._safe_extract(payload_path, extract_to)
            else:
                encrypted_data = self._read_encrypted_payload()
                if self.format_version == 3:
                    plaintext = decrypt_payload(
                        self.metadata["encryption"],
                        derived_key,
                        nonce,
                        encrypted_data,
                        metadata_associated_data(self.metadata),
                    )
                else:
                    associated_data = metadata_associated_data(self.metadata) if self.format_version == 2 else None
                    plaintext = AESGCM(derived_key).decrypt(nonce, encrypted_data, associated_data)
                compression_method = self.metadata.get("compression")
                if compression_method is not None:
                    plaintext = decompress_payload(plaintext)
                if len(plaintext) > MAX_PAYLOAD_BYTES:
                    raise ValueError("Decrypted payload exceeds the configured size limit.")
                self.suspicious_files = self._safe_extract(plaintext, extract_to)
        except InvalidTag:
            self._record_unlock_failure("authentication")
            if self.last_failure == "chunkhide_started":
                logger.warning("Three failed authentication attempts; recovery record saved.")
            else:
                logger.warning("Unlock failed: password or authenticated container metadata is invalid.")
            return False
        except (OSError, ValueError, zipfile.BadZipFile, KeyError, RuntimeError) as error:
            logger.error("Unlock or extraction failed: %s", error)
            return False
        finally:
            del derived_key

        self.failed_unlock_attempts = 0
        logger.info("Container safely extracted to %s.", os.path.abspath(extract_to))
        return True

    @staticmethod
    def _safe_extract(archive_bytes: bytes | str, extract_to: str):
        destination_root = os.path.realpath(os.path.abspath(extract_to))
        os.makedirs(destination_root, mode=0o700, exist_ok=True)
        if not os.path.isdir(destination_root):
            raise ValueError("Extraction destination is not a directory.")

        total_size = 0
        suspicious_files = []
        archive_source = archive_bytes if isinstance(archive_bytes, str) else io.BytesIO(archive_bytes)
        with zipfile.ZipFile(archive_source, "r") as payload_zip:
            members = payload_zip.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError("Archive contains too many entries.")
            member_names = [member.filename for member in members]
            if len(member_names) != len(set(member_names)):
                raise ValueError("Archive contains duplicate member paths.")

            for member in members:
                filename = member.filename
                windows_path = PureWindowsPath(filename)
                normalized_name = filename.replace("\\", "/")
                relative_path = PurePosixPath(normalized_name)
                if (
                    not filename
                    or "\x00" in filename
                    or ":" in filename
                    or windows_path.is_absolute()
                    or windows_path.drive
                    or relative_path.is_absolute()
                    or any(part == ".." for part in relative_path.parts)
                    or not relative_path.parts
                ):
                    raise ValueError(f"Unsafe archive member path: {filename!r}")

                if member.file_size < 0 or member.file_size > MAX_MEMBER_BYTES:
                    raise ValueError(f"Archive member exceeds the per-file size limit: {filename!r}")
                total_size += member.file_size
                if total_size > MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive exceeds the total extraction size limit.")
                if member.file_size and member.file_size / max(member.compress_size, 1) > MAX_EXPANSION_RATIO:
                    raise ValueError(f"Archive member exceeds the expansion-ratio limit: {filename!r}")

                unix_mode = (member.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(unix_mode)
                if stat.S_ISLNK(unix_mode) or file_type not in (0, stat.S_IFREG, stat.S_IFDIR):
                    raise ValueError(f"Special-file archive member is not allowed: {filename!r}")

                target_path = os.path.abspath(os.path.join(destination_root, *relative_path.parts))
                if os.path.commonpath((destination_root, target_path)) != destination_root:
                    raise ValueError(f"Archive member escapes the extraction directory: {filename!r}")
                parent_path = os.path.dirname(target_path)
                os.makedirs(parent_path, mode=0o700, exist_ok=True)
                if os.path.commonpath((destination_root, os.path.realpath(parent_path))) != destination_root:
                    raise ValueError(f"Archive member traverses a symbolic link: {filename!r}")

                if member.is_dir():
                    os.makedirs(target_path, mode=0o700, exist_ok=True)
                    if os.path.islink(target_path):
                        raise ValueError(f"Symbolic-link destination is not allowed: {filename!r}")
                    continue

                if suspicious_file_reasons(filename):
                    suspicious_files.append(filename)

                if os.path.lexists(target_path):
                    raise FileExistsError(f"Refusing to overwrite existing extraction target: {target_path}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
                flags |= getattr(os, "O_NOFOLLOW", 0)
                file_descriptor = os.open(target_path, flags, 0o600)
                written = 0
                try:
                    with os.fdopen(file_descriptor, "wb") as output_file:
                        with payload_zip.open(member, "r") as input_file:
                            while True:
                                chunk = input_file.read(1024 * 1024)
                                if not chunk:
                                    break
                                written += len(chunk)
                                if written > member.file_size or written > MAX_MEMBER_BYTES:
                                    raise ValueError(f"Archive member exceeded its declared size: {filename!r}")
                                output_file.write(chunk)
                    if written != member.file_size:
                        raise ValueError(f"Archive member size did not match its declaration: {filename!r}")
                except Exception:
                    if os.path.exists(target_path):
                        os.remove(target_path)
                    raise
        return suspicious_files

    @staticmethod
    def _recovery_root() -> str:
        if os.name == "nt":
            base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or os.path.expanduser("~")
        elif platform.system() == "Darwin":
            base = os.path.join(os.path.expanduser("~"), "Library", "Application Support")
        else:
            base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
        recovery_root = os.path.join(base, "KYSider", "Recovery")
        os.makedirs(recovery_root, mode=0o700, exist_ok=True)
        if os.path.islink(recovery_root):
            raise ValueError("Recovery directory must not be a symbolic link.")
        if os.name != "nt":
            os.chmod(recovery_root, 0o700)
        return os.path.realpath(recovery_root)

    @staticmethod
    def _open_exclusive(path: str):
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o600)
        return os.fdopen(descriptor, "wb")

    def scatter_container(self) -> str:
        if self.format_version not in (2, 3, 4, 5):
            raise ValueError("Persistent recovery sets require an authenticated container.")
        if os.path.islink(self.container_path) or not os.path.isfile(self.container_path):
            raise FileNotFoundError("Container is missing or is a symbolic link.")
        container_size = os.path.getsize(self.container_path)
        if container_size > MAX_CONTAINER_BYTES:
            raise ValueError("Container exceeds the recovery size limit.")

        recovery_root = self._recovery_root()
        recovery_directory = tempfile.mkdtemp(prefix="set-", dir=recovery_root)
        shard_records = []
        whole_digest = hashlib.sha256()
        chunk_size = container_size // 3
        chunk_sizes = (chunk_size, chunk_size, container_size - 2 * chunk_size)
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            container_descriptor = os.open(self.container_path, flags)
            with os.fdopen(container_descriptor, "rb") as container_file:
                for index, shard_size in enumerate(chunk_sizes):
                    shard_name = f"shard-{index}.bin"
                    shard_path = os.path.join(recovery_directory, shard_name)
                    shard_digest = hashlib.sha256()
                    remaining = shard_size
                    with self._open_exclusive(shard_path) as shard_file:
                        while remaining:
                            chunk = container_file.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise OSError("Container ended before all recovery shards were written.")
                            shard_file.write(chunk)
                            shard_digest.update(chunk)
                            whole_digest.update(chunk)
                            remaining -= len(chunk)
                    shard_records.append({
                        "name": shard_name,
                        "size": shard_size,
                        "sha256": shard_digest.hexdigest(),
                    })

            manifest = {
                "format_version": 1,
                "container_path": self.container_path,
                "container_size": container_size,
                "container_sha256": whole_digest.hexdigest(),
                "shards": shard_records,
            }
            manifest_data = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
            manifest["hmac_sha256"] = hmac.new(
                self.metadata["bound_id"].encode("utf-8"),
                manifest_data,
                hashlib.sha256,
            ).hexdigest()
            record_path = os.path.join(recovery_directory, "recovery.json")
            with self._open_exclusive(record_path) as record_file:
                record_file.write(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            os.remove(self.container_path)
        except Exception:
            shutil.rmtree(recovery_directory, ignore_errors=True)
            raise

        self.recovery_record_path = record_path
        self.shard_paths = [os.path.join(recovery_directory, item["name"]) for item in shard_records]
        logger.info("Recovery record created: %s", record_path)
        return record_path

    @classmethod
    def recover_from_record(cls, record_path: str, entered_boundid: str) -> str:
        if not isinstance(entered_boundid, str) or len(entered_boundid) < 32:
            raise ValueError("Recovery token is invalid.")
        if os.path.islink(record_path) or not os.path.isfile(record_path):
            raise FileNotFoundError("Recovery record is missing or is a symbolic link.")
        if os.path.getsize(record_path) > MAX_METADATA_BYTES:
            raise ValueError("Recovery record exceeds the size limit.")

        recovery_root = cls._recovery_root()
        recovery_directory = os.path.realpath(os.path.dirname(os.path.abspath(record_path)))
        if os.path.normcase(os.path.commonpath((recovery_root, recovery_directory))) != os.path.normcase(recovery_root):
            raise ValueError("Recovery record is outside the private recovery directory.")
        if os.path.islink(recovery_directory):
            raise ValueError("Recovery directory must not be a symbolic link.")

        record_flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        record_descriptor = os.open(record_path, record_flags)
        with os.fdopen(record_descriptor, "r", encoding="utf-8") as record_file:
            manifest = json.load(record_file)
        if not isinstance(manifest, dict) or manifest.get("format_version") != 1:
            raise ValueError("Unsupported recovery record format.")
        signature = manifest.pop("hmac_sha256", None)
        expected_signature = hmac.new(
            entered_boundid.encode("utf-8"),
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Recovery token or recovery record is invalid.")

        container_path = manifest.get("container_path")
        container_size = manifest.get("container_size")
        shards = manifest.get("shards")
        container_digest = manifest.get("container_sha256")
        if (
            not isinstance(container_path, str)
            or not os.path.isabs(container_path)
            or not isinstance(container_size, int)
            or not 0 < container_size <= MAX_CONTAINER_BYTES
            or not isinstance(container_digest, str)
            or len(container_digest) != 64
            or not isinstance(shards, list)
            or len(shards) != 3
        ):
            raise ValueError("Recovery record fields are malformed.")
        if os.path.lexists(container_path):
            raise FileExistsError("Refusing to overwrite an existing restored-container path.")
        destination_directory = os.path.dirname(container_path)
        if not os.path.isdir(destination_directory):
            raise FileNotFoundError("Original container directory is unavailable.")
        if os.path.realpath(destination_directory) != destination_directory:
            raise ValueError("Original container directory now resolves through a symbolic link.")

        total_shard_size = 0
        validated_shards = []
        for index, shard in enumerate(shards):
            if not isinstance(shard, dict):
                raise ValueError("Recovery shard record is malformed.")
            shard_name = shard.get("name")
            shard_size = shard.get("size")
            shard_digest = shard.get("sha256")
            if (
                shard_name != f"shard-{index}.bin"
                or not isinstance(shard_size, int)
                or shard_size < 0
                or not isinstance(shard_digest, str)
                or len(shard_digest) != 64
            ):
                raise ValueError("Recovery shard record is malformed.")
            shard_path = os.path.join(recovery_directory, shard_name)
            if os.path.islink(shard_path) or not os.path.isfile(shard_path) or os.path.getsize(shard_path) != shard_size:
                raise ValueError("Recovery shard is missing or has an invalid size.")
            total_shard_size += shard_size
            validated_shards.append((shard_path, shard_size, shard_digest))
        if total_shard_size != container_size:
            raise ValueError("Recovery shard lengths do not match the recorded container size.")

        descriptor, temporary_path = tempfile.mkstemp(
            prefix=".kysider-restored-",
            dir=destination_directory,
        )
        whole_digest = hashlib.sha256()
        try:
            with os.fdopen(descriptor, "wb") as output_file:
                for shard_path, shard_size, expected_shard_digest in validated_shards:
                    shard_digest = hashlib.sha256()
                    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                    shard_descriptor = os.open(shard_path, flags)
                    with os.fdopen(shard_descriptor, "rb") as shard_file:
                        remaining = shard_size
                        while remaining:
                            chunk = shard_file.read(min(1024 * 1024, remaining))
                            if not chunk:
                                raise ValueError("Recovery shard ended unexpectedly.")
                            output_file.write(chunk)
                            shard_digest.update(chunk)
                            whole_digest.update(chunk)
                            remaining -= len(chunk)
                    if not hmac.compare_digest(shard_digest.hexdigest(), expected_shard_digest):
                        raise ValueError("Recovery shard integrity check failed.")
            if not hmac.compare_digest(whole_digest.hexdigest(), container_digest):
                raise ValueError("Restored container integrity check failed.")

            restored_metadata = cls._read_metadata(temporary_path)
            if validate_metadata(restored_metadata) not in (2, 3, 4, 5) or not hmac.compare_digest(
                restored_metadata["bound_id"], entered_boundid
            ):
                raise ValueError("Recovery token does not match the restored container.")
            os.link(temporary_path, container_path)
        finally:
            if os.path.exists(temporary_path):
                os.remove(temporary_path)

        restored_digest = hashlib.sha256()
        with open(container_path, "rb") as restored_file:
            for chunk in iter(lambda: restored_file.read(1024 * 1024), b""):
                restored_digest.update(chunk)
        if (
            os.path.getsize(container_path) != container_size
            or not hmac.compare_digest(restored_digest.hexdigest(), container_digest)
        ):
            os.remove(container_path)
            raise ValueError("Restored container size or hash verification failed.")
        logger.info("Container integrity verified after recovery: %s", container_path)
        return container_path

    def process_recovery(self, entered_boundid: str) -> bool:
        if not self.recovery_record_path:
            return False
        restored_path = self.recover_from_record(self.recovery_record_path, entered_boundid)
        self.container_path = restored_path
        self.metadata = self._load_metadata()
        return True

if __name__ == "__main__":
    from kysider_gui import main

    sys.exit(main())