import gzip
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from netapp_asup_alertcheck.archive import ArchiveError, ArchiveReader


class ArchiveReaderTests(unittest.TestCase):
    def test_zip_lists_names_and_reads_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("manifest.txt", "alpha\nbeta\n")
                archive.writestr("nested/data.txt", "payload")

            reader = ArchiveReader(archive_path)

            self.assertEqual(reader.list_names(), ["manifest.txt", "nested/data.txt"])
            self.assertEqual(reader.read_text("manifest.txt"), "alpha\nbeta\n")

    def test_gzip_lists_basename_without_gz_and_decodes_with_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "EMS-LOG-FILE.gz"
            archive_path.write_bytes(gzip.compress(b"good\xfftext"))

            reader = ArchiveReader(archive_path)

            self.assertEqual(reader.list_names(), ["EMS-LOG-FILE"])
            self.assertEqual(reader.read_text("EMS-LOG-FILE"), "good\ufffdtext")

    def test_missing_archive_raises_archive_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "missing.zip"

            with self.assertRaises(ArchiveError):
                ArchiveReader(archive_path)

    def test_unsupported_suffix_raises_archive_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.rar"
            archive_path.write_text("nope", encoding="utf-8")

            reader = ArchiveReader(archive_path)

            with self.assertRaises(ArchiveError):
                reader.list_names()
            with self.assertRaises(ArchiveError):
                reader.read_text("anything")

    def test_tar_lists_file_members_and_reads_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "sample.tar"
            data_path = root / "data.txt"
            data_path.write_text("tar text", encoding="utf-8")
            directory_path = root / "folder"
            directory_path.mkdir()
            with tarfile.open(archive_path, "w") as archive:
                archive.add(directory_path, arcname="folder")
                archive.add(data_path, arcname="folder/data.txt")

            reader = ArchiveReader(archive_path)

            self.assertEqual(reader.list_names(), ["folder/data.txt"])
            self.assertEqual(reader.read_text("folder/data.txt"), "tar text")

    def test_tgz_lists_file_members_and_reads_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive_path = root / "sample.tgz"
            data_path = root / "data.txt"
            data_path.write_text("tgz text", encoding="utf-8")
            with tarfile.open(archive_path, "w:gz") as archive:
                archive.add(data_path, arcname="data.txt")

            reader = ArchiveReader(archive_path)

            self.assertEqual(reader.list_names(), ["data.txt"])
            self.assertEqual(reader.read_text("data.txt"), "tgz text")

    def test_7z_lists_members_ignoring_archive_path_and_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.7z"
            archive_path.write_bytes(b"fake 7z")
            output = "\n".join(
                [
                    f"Path = {archive_path}",
                    "Type = 7z",
                    "Path = sample.7z",
                    "Path = arw-vol-status.xml",
                    "Path = folder/EMS-LOG-FILE.gz",
                ]
            )
            result = Mock(returncode=0, stdout=output, stderr="")

            with patch("netapp_asup_alertcheck.archive.subprocess.run", return_value=result) as run:
                names = ArchiveReader(archive_path).list_names()

            self.assertEqual(names, ["arw-vol-status.xml", "folder/EMS-LOG-FILE.gz"])
            run.assert_called_once_with(
                ["7z", "l", "-slt", str(archive_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_7z_read_text_decompresses_gzip_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.7z"
            archive_path.write_bytes(b"fake 7z")
            result = Mock(returncode=0, stdout=gzip.compress("event text".encode("utf-8")), stderr=b"")

            with patch("netapp_asup_alertcheck.archive.subprocess.run", return_value=result) as run:
                text = ArchiveReader(archive_path).read_text("EMS-LOG-FILE.gz")

            self.assertEqual(text, "event text")
            run.assert_called_once_with(
                ["7z", "x", "-so", str(archive_path), "EMS-LOG-FILE.gz"],
                capture_output=True,
                check=False,
            )
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_7z_list_nonzero_raises_archive_error_with_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.7z"
            archive_path.write_bytes(b"fake 7z")
            result = Mock(returncode=2, stdout="", stderr="cannot open archive")

            with patch("netapp_asup_alertcheck.archive.subprocess.run", return_value=result):
                with self.assertRaisesRegex(ArchiveError, "list.*cannot open archive"):
                    ArchiveReader(archive_path).list_names()

    def test_7z_list_os_error_raises_archive_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.7z"
            archive_path.write_bytes(b"fake 7z")

            with patch("netapp_asup_alertcheck.archive.subprocess.run", side_effect=OSError("missing 7z")):
                with self.assertRaisesRegex(ArchiveError, "list.*missing 7z"):
                    ArchiveReader(archive_path).list_names()

    def test_7z_read_nonzero_raises_archive_error_with_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "sample.7z"
            archive_path.write_bytes(b"fake 7z")
            result = Mock(returncode=2, stdout=b"", stderr=b"member not found")

            with patch("netapp_asup_alertcheck.archive.subprocess.run", return_value=result):
                with self.assertRaisesRegex(ArchiveError, "read.*member not found"):
                    ArchiveReader(archive_path).read_text("EMS-LOG-FILE.gz")


if __name__ == "__main__":
    unittest.main()
