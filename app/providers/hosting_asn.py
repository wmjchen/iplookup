from __future__ import annotations

from pathlib import Path


class HostingAsnIndex:
    def __init__(self, path: Path | None = None, asns: set[int] | None = None) -> None:
        if asns is not None:
            self._asns = asns
        elif path is not None and path.exists():
            self._asns = self._load(path)
        else:
            self._asns = set()

    @staticmethod
    def _load(path: Path) -> set[int]:
        result: set[int] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.upper().startswith("AS,"):
                continue
            # formats: "AS16509" or "AS16509,12345" or "16509"
            token = line.split(",")[0].strip().upper()
            if token.startswith("AS"):
                token = token[2:]
            try:
                result.add(int(token))
            except ValueError:
                continue
        return result

    def contains(self, asn: int | str | None) -> bool:
        if asn is None:
            return False
        if isinstance(asn, str):
            token = asn.strip().upper()
            if token.startswith("AS"):
                token = token[2:]
            try:
                asn_num = int(token)
            except ValueError:
                return False
        else:
            asn_num = asn
        return asn_num in self._asns

    def __len__(self) -> int:
        return len(self._asns)
