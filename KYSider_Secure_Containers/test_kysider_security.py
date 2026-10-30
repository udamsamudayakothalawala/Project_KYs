import hashlib
import io
import json
import os
import secrets
import tempfile
import zipfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from kysider_compression import (
    _MAGIC,
    _huffman_encode,
    _lz77_encode,
    _lzss_encode,
    compress_payload,
    decompress_payload,
)
from kysider_extractor import KYSiderExtractor
from kysider_keys import (
    RECIPIENT_KEY_METHODS,
    generate_recipient_keypair,
    load_recipient_private_key,
    recipient_key_id,
    save_recipient_private_key,
    save_recipient_public_key,
)
from kysider_packager import KYSiderPackager
from kysider_security import (
    format_container_security_report,
    inspect_source_path,
    legacy_hardware_fingerprint,
    metadata_associated_data,
)


class KYSiderSecurityTests(TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(prefix="kysider-tests-")
        self.root = Path(self.temporary_directory.name)
        self.source_directory = self.root / "source"
        self.source_directory.mkdir()
        (self.source_directory / "note.txt").write_text("secure payload", encoding="utf-8")
        self.container_path = self.root / "vault.kysd"
        self.password = "test-password"
        self.packager = KYSiderPackager(str(self.container_path))
        self.packager.create_container(str(self.source_directory), self.password)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_v4_metadata_is_authenticated_and_has_no_embedded_encid(self):
        with zipfile.ZipFile(self.container_path) as container:
            metadata = json.loads(container.read("metadata.json"))
            payload = container.read("payload.enc")
        self.assertEqual(metadata["format_version"], 4)
        self.assertEqual(metadata["encryption"], "AES-256-GCM")
        self.assertEqual(metadata["compression"], "deflate-blocks-v1")
        self.assertEqual(metadata["chunk_count"], (metadata["compressed_size"] + 1024 * 1024 - 1) // (1024 * 1024))
        self.assertNotIn("password_hash", metadata)
        self.assertNotIn("enc_id", metadata)
        self.assertNotIn("verify_id", metadata)

        metadata["bound_id"] = "Z" * 43
        tampered_path = self.root / "tampered.kysd"
        with zipfile.ZipFile(tampered_path, "w", zipfile.ZIP_STORED) as container:
            container.writestr("metadata.json", json.dumps(metadata))
            container.writestr("payload.enc", payload)
        original_bytes = self.container_path.read_bytes()
        self.assertFalse(
            KYSiderExtractor(str(tampered_path)).unlock(
                self.password,
                self.packager.enc_id,
                str(self.root / "out"),
            )
        )
        self.assertEqual(self.container_path.read_bytes(), original_bytes)
        self.assertTrue(tampered_path.exists())

    def test_both_supported_ciphers_unlock_with_password_and_encid(self):
        for method in ("AES-256-GCM", "ChaCha20-Poly1305"):
            with self.subTest(method=method):
                package = KYSiderPackager(str(self.root / f"{method}.kysd"), method)
                package.create_container(str(self.source_directory), self.password)
                extraction_path = self.root / method.replace("-", "_")
                extractor = KYSiderExtractor(package.container_name)
                self.assertTrue(extractor.unlock(self.password, package.enc_id, str(extraction_path)))
                self.assertEqual((extraction_path / "note.txt").read_text(encoding="utf-8"), "secure payload")

    def test_parallel_streaming_round_trips_large_multi_block_payload(self):
        source_path = self.root / "large.bin"
        source_path.write_bytes(os.urandom(2 * 1024 * 1024 + 137))
        container_path = self.root / "large.kysd"
        package = KYSiderPackager(str(container_path))
        package.create_container(str(source_path), self.password)

        with zipfile.ZipFile(container_path) as container:
            metadata = json.loads(container.read("metadata.json"))
        self.assertGreater(metadata["compression_block_count"], 1)
        self.assertGreater(metadata["chunk_count"], 1)

        extraction_path = self.root / "large-output"
        self.assertTrue(
            KYSiderExtractor(str(container_path)).unlock(
                self.password,
                package.enc_id,
                str(extraction_path),
            )
        )
        self.assertEqual((extraction_path / "large.bin").read_bytes(), source_path.read_bytes())

    def test_container_security_report_describes_encryption_without_exposing_ids(self):
        report = format_container_security_report(self.packager_metadata(), 4096)
        self.assertIn("Format version: 4", report)
        self.assertIn("Encryption: AES-256-GCM", report)
        self.assertIn("EncID required: yes", report)
        self.assertNotIn(self.packager.enc_id, report)
        self.assertNotIn(self.packager.bound_id, report)

    def packager_metadata(self):
        with zipfile.ZipFile(self.container_path) as container:
            return json.loads(container.read("metadata.json"))

    def test_suspicious_source_scan_and_extraction_return_warning_paths(self):
        suspicious_source = self.source_directory / "run-me.exe"
        suspicious_source.write_bytes(b"not executed")
        source_findings, source_count = inspect_source_path(str(self.source_directory))
        self.assertEqual(source_count, 1)
        self.assertEqual(source_findings, ["run-me.exe"])

        archive_buffer = io.BytesIO()
        with zipfile.ZipFile(archive_buffer, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("tools/run-me.ps1", "Write-Output safe")
            archive.writestr("notes.txt", "ordinary text")
        extracted = self.root / "suspicious-output"
        findings = KYSiderExtractor._safe_extract(archive_buffer.getvalue(), str(extracted))
        self.assertEqual(findings, ["tools/run-me.ps1"])

    def test_recipient_key_wrapping_round_trips_all_supported_methods(self):
        for method in RECIPIENT_KEY_METHODS:
            with self.subTest(method=method):
                public_key, private_key = generate_recipient_keypair(method)
                key_id = recipient_key_id(method, public_key)
                public_path = self.root / f"{method.replace(' ', '_')}.public.json"
                private_path = self.root / f"{method.replace(' ', '_')}.private.json"
                save_recipient_public_key(str(public_path), method, public_key)
                save_recipient_private_key(
                    str(private_path),
                    method,
                    private_key,
                    key_id,
                    "separate-key-passphrase",
                )
                if method == RECIPIENT_KEY_METHODS[0]:
                    with self.assertRaises(ValueError):
                        load_recipient_private_key(
                            str(private_path),
                            "incorrect-key-passphrase",
                            method,
                        )
                container_path = self.root / f"{method.replace(' ', '_')}.kysd"
                package = KYSiderPackager(str(container_path))
                package.create_container(
                    str(self.source_directory),
                    self.password,
                    key_wrapping_method=method,
                    recipient_public_key_path=str(public_path),
                )

                with zipfile.ZipFile(container_path) as container:
                    metadata = json.loads(container.read("metadata.json"))
                self.assertEqual(metadata["format_version"], 5)
                self.assertEqual(metadata["key_wrapping"], method)
                self.assertNotIn("maker_hwid", metadata)
                self.assertNotIn(self.password, json.dumps(metadata))
                report = format_container_security_report(metadata, os.path.getsize(container_path))
                self.assertIn("Hardware binding: disabled for recipient portability", report)
                self.assertIn(f"Recipient key wrapping: {method}", report)

                extraction_path = self.root / f"{method.replace(' ', '_')}-recipient"
                with patch(
                    "kysider_extractor.generate_hardware_fingerprint",
                    side_effect=AssertionError("Recipient containers must not require maker hardware binding."),
                ):
                    self.assertTrue(
                        KYSiderExtractor(str(container_path)).unlock(
                            self.password,
                            package.enc_id,
                            str(extraction_path),
                            str(private_path),
                            "separate-key-passphrase",
                        )
                    )
                self.assertEqual(
                    (extraction_path / "note.txt").read_text(encoding="utf-8"),
                    "secure payload",
                )

    def test_blank_encid_counts_to_three_attempt_chunkhide(self):
        original_bytes = self.container_path.read_bytes()
        local_app_data = self.root / "local-app-data"
        with patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}):
            extractor = KYSiderExtractor(str(self.container_path))
            self.assertFalse(extractor.unlock(self.password, ""))
            self.assertTrue(self.container_path.exists())
            self.assertFalse(extractor.unlock(self.password, ""))
            self.assertTrue(self.container_path.exists())
            self.assertFalse(extractor.unlock(self.password, ""))
            self.assertFalse(self.container_path.exists())
            self.assertIsNotNone(extractor.recovery_record_path)
            restored_path = KYSiderExtractor.recover_from_record(
                extractor.recovery_record_path,
                self.packager.bound_id,
            )

        self.assertEqual(Path(restored_path).read_bytes(), original_bytes)

    def test_legacy_container_remains_readable(self):
        password = "legacy-password"
        payload_buffer = io.BytesIO()
        with zipfile.ZipFile(payload_buffer, "w", zipfile.ZIP_DEFLATED) as payload_zip:
            payload_zip.writestr("legacy.txt", "legacy payload")
        original_payload = payload_buffer.getvalue()
        lz77_stream = _lz77_encode(original_payload)
        lzss_stream = _lzss_encode(lz77_stream)
        code_lengths, huffman_stream = _huffman_encode(lzss_stream)
        compressed_payload = (
            _MAGIC
            + b"\x01"
            + len(original_payload).to_bytes(8, "big")
            + len(lz77_stream).to_bytes(8, "big")
            + len(lzss_stream).to_bytes(8, "big")
            + code_lengths
            + huffman_stream
        )
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        metadata = {
            "maker_hwid": legacy_hardware_fingerprint(),
            "password_hash": hashlib.sha256(password.encode("utf-8")).hexdigest(),
            "bound_id": "BOUND-ABCDEF12",
            "compression": "lz77-lzss-huffman-v1",
            "salt": salt.hex(),
            "nonce": nonce.hex(),
        }
        key = self.packager._derive_key(password, salt)
        encrypted_payload = AESGCM(key).encrypt(nonce, compressed_payload, None)
        legacy_path = self.root / "legacy.kysd"
        with zipfile.ZipFile(legacy_path, "w", zipfile.ZIP_DEFLATED) as container:
            container.writestr("metadata.json", json.dumps(metadata))
            container.writestr("payload.enc", encrypted_payload)

        extraction_path = self.root / "legacy-output"
        self.assertTrue(KYSiderExtractor(str(legacy_path)).unlock(password, "", str(extraction_path)))
        self.assertEqual((extraction_path / "legacy.txt").read_text(encoding="utf-8"), "legacy payload")

    def test_authenticated_format_two_remains_readable(self):
        password = "format-two-password"
        payload_buffer = io.BytesIO()
        with zipfile.ZipFile(payload_buffer, "w", zipfile.ZIP_STORED) as payload_zip:
            payload_zip.writestr("format-two.txt", "old authenticated format")
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        metadata = {
            "format_version": 2,
            "maker_hwid": self.packager.maker_hwid,
            "bound_id": secrets.token_urlsafe(32),
            "verify_id": secrets.token_hex(32),
            "compression": "deflate-lz77-huffman-v1",
            "salt": salt.hex(),
            "nonce": nonce.hex(),
        }
        key = self.packager._derive_key(password, salt)
        encrypted_payload = AESGCM(key).encrypt(
            nonce,
            compress_payload(payload_buffer.getvalue()),
            metadata_associated_data(metadata),
        )
        container_path = self.root / "format-two.kysd"
        with zipfile.ZipFile(container_path, "w", zipfile.ZIP_STORED) as container:
            container.writestr("metadata.json", json.dumps(metadata))
            container.writestr("payload.enc", encrypted_payload)

        extraction_path = self.root / "format-two-output"
        self.assertTrue(KYSiderExtractor(str(container_path)).unlock(password, "", str(extraction_path)))
        self.assertEqual(
            (extraction_path / "format-two.txt").read_text(encoding="utf-8"),
            "old authenticated format",
        )

    def test_wrong_password_does_not_modify_container(self):
        original_bytes = self.container_path.read_bytes()
        extractor = KYSiderExtractor(str(self.container_path))
        self.assertFalse(extractor.unlock("wrong-password", self.packager.enc_id, str(self.root / "wrong")))
        self.assertEqual(self.container_path.read_bytes(), original_bytes)

    def test_wrong_encid_does_not_modify_container_before_third_attempt(self):
        original_bytes = self.container_path.read_bytes()
        extractor = KYSiderExtractor(str(self.container_path))
        self.assertFalse(extractor.unlock(self.password, "wrong-encid"))
        self.assertEqual(extractor.failed_unlock_attempts, 1)
        self.assertTrue(self.container_path.exists())
        self.assertEqual(self.container_path.read_bytes(), original_bytes)
    def test_third_failed_password_starts_recoverable_chunkhide(self):
        local_app_data = self.root / "local-app-data"
        original_bytes = self.container_path.read_bytes()
        with patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}):
            extractor = KYSiderExtractor(str(self.container_path))
            self.assertFalse(extractor.unlock("wrong-one", self.packager.enc_id))
            self.assertTrue(self.container_path.exists())
            self.assertFalse(extractor.unlock("wrong-two", self.packager.enc_id))
            self.assertTrue(self.container_path.exists())
            self.assertFalse(extractor.unlock("wrong-three", self.packager.enc_id))
            self.assertFalse(self.container_path.exists())
            self.assertIsNotNone(extractor.recovery_record_path)

            restored_path = KYSiderExtractor.recover_from_record(
                extractor.recovery_record_path,
                self.packager.bound_id,
            )
            restored_extractor = KYSiderExtractor(restored_path)
            self.assertTrue(
                restored_extractor.unlock(
                    self.password,
                    self.packager.enc_id,
                    str(self.root / "retry-output"),
                )
            )

        self.assertEqual(Path(restored_path).read_bytes(), original_bytes)

    def test_zip_slip_and_duplicate_members_are_rejected(self):
        malicious_archive = io.BytesIO()
        with zipfile.ZipFile(malicious_archive, "w") as archive:
            archive.writestr("../escape.txt", "outside")
        self.assertRaises(
            ValueError,
            KYSiderExtractor._safe_extract,
            malicious_archive.getvalue(),
            str(self.root / "safe"),
        )
        self.assertFalse((self.root / "escape.txt").exists())

        duplicate_archive = io.BytesIO()
        with zipfile.ZipFile(duplicate_archive, "w") as archive:
            archive.writestr("same.txt", "first")
            archive.writestr("same.txt", "second")
        self.assertRaises(
            ValueError,
            KYSiderExtractor._safe_extract,
            duplicate_archive.getvalue(),
            str(self.root / "duplicate"),
        )

    def test_decompression_rejects_oversized_declared_output(self):
        hostile_stream = _MAGIC + b"\x02" + (2**64 - 1).to_bytes(8, "big") + b"not-zlib"
        self.assertRaises(ValueError, decompress_payload, hostile_stream)

    def test_payload_temp_isolation_and_no_overwrite(self):
        destination = self.source_directory / "inside-source.kysd"
        packager = KYSiderPackager(str(destination))
        packager.create_container(str(self.source_directory), self.password, overwrite=True)

        extract_directory = self.root / "self-inclusion-check"
        self.assertTrue(
            KYSiderExtractor(str(destination)).unlock(
                self.password,
                packager.enc_id,
                str(extract_directory),
            )
        )
        self.assertEqual(sorted(path.name for path in extract_directory.iterdir()), ["note.txt"])
        self.assertRaises(FileExistsError, packager.create_container, str(self.source_directory), self.password)

    def test_payload_temp_inside_source_is_not_archived(self):
        nested_temp = self.source_directory / "temporary"
        nested_temp.mkdir()
        destination = self.root / "nested-temp.kysd"
        packager = KYSiderPackager(str(destination))
        with patch.object(KYSiderPackager, "_payload_temp_parent", return_value=str(nested_temp)):
            packager.create_container(str(self.source_directory), self.password)

        extract_directory = self.root / "nested-temp-check"
        self.assertTrue(
            KYSiderExtractor(str(destination)).unlock(
                self.password,
                packager.enc_id,
                str(extract_directory),
            )
        )
        self.assertEqual(sorted(path.name for path in extract_directory.iterdir()), ["note.txt"])

    def test_source_symlinks_are_skipped(self):
        external_file = self.root / "outside.txt"
        external_file.write_text("outside source", encoding="utf-8")
        link_path = self.source_directory / "linked.txt"
        try:
            os.symlink(external_file, link_path)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links are unavailable in this environment.")

        destination = self.root / "symlink-check.kysd"
        extract_directory = self.root / "symlink-output"
        package = KYSiderPackager(str(destination))
        package.create_container(str(self.source_directory), self.password)
        self.assertTrue(
            KYSiderExtractor(str(destination)).unlock(
                self.password,
                package.enc_id,
                str(extract_directory),
            )
        )
        self.assertFalse((extract_directory / "linked.txt").exists())

    def test_recovery_survives_restart_and_verifies_all_shards(self):
        original_bytes = self.container_path.read_bytes()
        local_app_data = self.root / "local-app-data"
        with patch.dict(os.environ, {"LOCALAPPDATA": str(local_app_data)}):
            extractor = KYSiderExtractor(str(self.container_path))
            record_path = extractor.scatter_container()
            manifest = json.loads(Path(record_path).read_text(encoding="utf-8"))
            self.assertEqual(sum(shard["size"] for shard in manifest["shards"]), len(original_bytes))
            first_shard = Path(record_path).parent / manifest["shards"][0]["name"]
            original_shard = first_shard.read_bytes()
            first_shard.write_bytes(original_shard[:-1])
            self.assertRaises(
                ValueError,
                KYSiderExtractor.recover_from_record,
                record_path,
                self.packager.bound_id,
            )
            first_shard.write_bytes(original_shard)
            self.assertRaises(
                ValueError,
                KYSiderExtractor.recover_from_record,
                record_path,
                "Z" * 43,
            )
            restored_path = KYSiderExtractor.recover_from_record(record_path, self.packager.bound_id)

        self.assertEqual(Path(restored_path).read_bytes(), original_bytes)
        self.assertEqual(Path(restored_path).stat().st_size, len(original_bytes))


if __name__ == "__main__":
    import unittest

    unittest.main()