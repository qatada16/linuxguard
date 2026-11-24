import gzip
import os
from collections.abc import Iterator
from pathlib import Path


def read_lines(path: str | Path) -> Iterator[str]:
    file_path = Path(path)
    opener = gzip.open if file_path.suffix == ".gz" else open
    with opener(file_path, "rt", encoding="utf-8", errors="replace") as handle:
        yield from handle


class FileFollower:
    def __init__(self, path: str | Path, start_at_end: bool = True) -> None:
        self._path = Path(path)
        self._start_at_end = start_at_end
        self._position = 0
        self._identity: tuple[int, int] | None = None
        self._partial = b""

    @property
    def path(self) -> Path:
        return self._path

    def poll(self) -> list[str]:
        try:
            status = os.stat(self._path)
        except FileNotFoundError:
            return []
        identity = (status.st_dev, status.st_ino)
        if self._identity is None:
            self._identity = identity
            self._position = status.st_size if self._start_at_end else 0
        elif identity != self._identity or status.st_size < self._position:
            self._identity = identity
            self._position = 0
            self._partial = b""
        if status.st_size == self._position:
            return []
        with open(self._path, "rb") as handle:
            handle.seek(self._position)
            chunk = handle.read()
            self._position = handle.tell()
        pieces = (self._partial + chunk).split(b"\n")
        self._partial = pieces.pop()
        return [piece.decode("utf-8", errors="replace").rstrip("\r") for piece in pieces if piece.strip()]
