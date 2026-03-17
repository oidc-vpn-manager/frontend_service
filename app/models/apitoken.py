"""
ApiToken model for M2M API authentication (VULN-03).

Tokens are hashed with argon2id before storage.  The plaintext is only
ever returned at creation time.
"""
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.extensions import db

_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)


class ApiToken(db.Model):
    __tablename__ = "api_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(512), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False)
    created_by = db.Column(db.String(255), nullable=False)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    expires_at = db.Column(db.DateTime, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)
    is_revoked = db.Column(db.Boolean, nullable=False, default=False)

    @classmethod
    def create(cls, *, plaintext_key: str, description: str,
               created_by: str, expires_at: datetime) -> "ApiToken":
        """Hash *plaintext_key* and return an unsaved ApiToken instance."""
        return cls(
            token_hash=_hasher.hash(plaintext_key),
            description=description,
            created_by=created_by,
            expires_at=expires_at,
        )

    def verify_key(self, plaintext_key: str) -> bool:
        """Return True if *plaintext_key* matches the stored hash."""
        try:
            return _hasher.verify(self.token_hash, plaintext_key)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def is_valid(self) -> bool:
        """Return True if the token is not revoked and not expired."""
        if self.is_revoked:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now < expires

    def revoke(self) -> None:
        self.is_revoked = True
