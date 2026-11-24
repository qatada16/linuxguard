from pathlib import Path

UNSET_ID = 4294967295


class UserResolver:
    def __init__(self, names_by_uid: dict[int, str] | None = None) -> None:
        self._names_by_uid = {0: "root", **(names_by_uid or {})}

    @classmethod
    def from_passwd_file(cls, path: str | Path) -> "UserResolver":
        passwd_path = Path(path)
        if not passwd_path.is_file():
            return cls()
        names: dict[int, str] = {}
        for line in passwd_path.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 3 and parts[2].isdigit():
                names[int(parts[2])] = parts[0]
        return cls(names)

    def name_for(self, uid: int | None) -> str | None:
        if uid is None or uid == UNSET_ID:
            return None
        return self._names_by_uid.get(uid, str(uid))


def parse_identifier(value: str | None) -> int | None:
    if value is None or not value.lstrip("-").isdigit():
        return None
    number = int(value)
    if number < 0 or number == UNSET_ID:
        return None
    return number
