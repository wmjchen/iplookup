from __future__ import annotations

from typing import Protocol, runtime_checkable

from app.core.models import ProviderResult


@runtime_checkable
class Provider(Protocol):
    provider_id: str

    async def lookup(self, ip: str) -> ProviderResult: ...
