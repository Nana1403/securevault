"""Validated data models."""

from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CredentialInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    account_name: str = Field(min_length=1, max_length=120)
    website: str = Field(default="", max_length=500)
    username: str = Field(default="", max_length=500)
    password: str = Field(min_length=1, max_length=2048)
    category: str = Field(default="Other", max_length=80)
    tags: str = Field(default="", max_length=500)
    notes: str = Field(default="", max_length=5000)
    favorite: bool = False

    @field_validator("category")
    @classmethod
    def normalize_category(cls, value: str) -> str:
        return value or "Other"


class Credential(CredentialInput):
    id: int
    created_at: str
    updated_at: str


class VaultHealth(BaseModel):
    total: int
    weak: int
    reused: int
    old: int
    incomplete: int
    score: int
