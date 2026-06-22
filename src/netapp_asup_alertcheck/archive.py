from __future__ import annotations

import gzip
import subprocess
import tarfile
import zipfile
from pathlib import Path


class ArchiveError(RuntimeError):
    """Raised when an archive cannot be read."""


class ArchiveReader:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if not self.path.exists():
            raise ArchiveError(f"Archive does not exist: {self.path}")

    def list_names(self) -> list[str]:
        kind = self._kind()
        if kind == "zip":
            return self._zip_names()
        if kind == "tar":
            return self._tar_names()
        if kind == "gz":
            return [self._gzip_member_name()]
        if kind == "7z":
            return self._seven_zip_names()
        raise ArchiveError(f"Unsupported archive format: {self.path}")

    def read_text(self, name: str) -> str:
        kind = self._kind()
        if kind == "zip":
            data = self._read_zip_member(name)
        elif kind == "tar":
            data = self._read_tar_member(name)
        elif kind == "gz":
            data = self._read_gzip_member(name)
        elif kind == "7z":
            data = self._read_seven_zip_member(name)
            if name.endswith(".gz"):
                try:
                    data = gzip.decompress(data)
                except OSError as exc:
                    raise ArchiveError(f"Could not decompress gzip member: {name}") from exc
        else:
            raise ArchiveError(f"Unsupported archive format: {self.path}")
        return data.decode("utf-8", errors="replace")

    def _kind(self) -> str:
        name = self.path.name.lower()
        if name.endswith(".zip"):
            return "zip"
        if name.endswith((".tar", ".tgz", ".tar.gz")):
            return "tar"
        if name.endswith(".gz"):
            return "gz"
        if name.endswith(".7z"):
            return "7z"
        return "unsupported"

    def _zip_names(self) -> list[str]:
        try:
            with zipfile.ZipFile(self.path) as archive:
                return archive.namelist()
        except zipfile.BadZipFile as exc:
            raise ArchiveError(f"Could not read zip archive: {self.path}") from exc

    def _read_zip_member(self, name: str) -> bytes:
        try:
            with zipfile.ZipFile(self.path) as archive:
                return archive.read(name)
        except (KeyError, zipfile.BadZipFile) as exc:
            raise ArchiveError(f"Could not read zip member: {name}") from exc

    def _tar_names(self) -> list[str]:
        try:
            with tarfile.open(self.path) as archive:
                return [member.name for member in archive.getmembers() if member.isfile()]
        except tarfile.TarError as exc:
            raise ArchiveError(f"Could not read tar archive: {self.path}") from exc

    def _read_tar_member(self, name: str) -> bytes:
        try:
            with tarfile.open(self.path) as archive:
                member = archive.getmember(name)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ArchiveError(f"Tar member is not a file: {name}")
                return extracted.read()
        except KeyError as exc:
            raise ArchiveError(f"Could not find tar member: {name}") from exc
        except tarfile.TarError as exc:
            raise ArchiveError(f"Could not read tar member: {name}") from exc

    def _gzip_member_name(self) -> str:
        return self.path.name[:-3]

    def _read_gzip_member(self, name: str) -> bytes:
        expected_name = self._gzip_member_name()
        if name != expected_name:
            raise ArchiveError(f"Could not find gzip member: {name}")
        try:
            with gzip.open(self.path, "rb") as archive:
                return archive.read()
        except OSError as exc:
            raise ArchiveError(f"Could not read gzip archive: {self.path}") from exc

    def _seven_zip_names(self) -> list[str]:
        try:
            result = subprocess.run(
                ["7z", "l", "-slt", str(self.path)],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise ArchiveError(f"Could not list 7z archive: {self.path}: {exc}") from exc
        if result.returncode != 0:
            stderr = _stderr_text(result.stderr)
            detail = f": {stderr}" if stderr else ""
            raise ArchiveError(f"Could not list 7z archive: {self.path}{detail}")

        output = result.stdout

        names: list[str] = []
        archive_headers = {str(self.path), self.path.name}
        for line in output.splitlines():
            if not line.startswith("Path = "):
                continue
            candidate = line[len("Path = ") :]
            if candidate and candidate not in archive_headers:
                names.append(candidate)
        return names

    def _read_seven_zip_member(self, name: str) -> bytes:
        try:
            result = subprocess.run(
                ["7z", "x", "-so", str(self.path), name],
                capture_output=True,
                check=False,
            )
        except OSError as exc:
            raise ArchiveError(f"Could not read 7z member: {name}: {exc}") from exc
        if result.returncode != 0:
            stderr = _stderr_text(result.stderr)
            detail = f": {stderr}" if stderr else ""
            raise ArchiveError(f"Could not read 7z member: {name}{detail}")
        return result.stdout


def _stderr_text(stderr: str | bytes | None) -> str:
    if stderr is None:
        return ""
    if isinstance(stderr, bytes):
        return stderr.decode("utf-8", errors="replace").strip()
    return stderr.strip()
