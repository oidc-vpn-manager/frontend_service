"""Widen presharedkey.key_hash from String(64) to String(255) for argon2id

VULN-15: SHA-256 hashes are 64 hex chars; argon2id hashes are ~96 chars.
Widens the column so existing SHA-256 rows remain valid and new argon2id
hashes are stored correctly.

Revision ID: d7e8f9a0b1c2
Revises: c1f3a2b4d5e6
Create Date: 2026-03-17 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd7e8f9a0b1c2'
down_revision = 'c1f3a2b4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('pre_shared_keys', schema=None) as batch_op:
        batch_op.alter_column(
            'key_hash',
            existing_type=sa.String(length=64),
            type_=sa.String(length=255),
            existing_nullable=False,
        )


def downgrade():
    with op.batch_alter_table('pre_shared_keys', schema=None) as batch_op:
        batch_op.alter_column(
            'key_hash',
            existing_type=sa.String(length=255),
            type_=sa.String(length=64),
            existing_nullable=False,
        )
