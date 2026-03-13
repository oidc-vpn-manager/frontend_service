"""Add user_groups to download_tokens

Stores the authenticated user's OIDC group memberships as a JSON text field
on DownloadToken. Used by the download route to select the appropriate
OpenVPN template based on group membership, and supports both the CLI
workflow and the WEB_AUTH (OpenVPN Connect) provisioning flow.

Revision ID: c1f3a2b4d5e6
Revises: a4166104da13
Create Date: 2026-03-13 07:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1f3a2b4d5e6'
down_revision = 'a4166104da13'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('download_tokens', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_groups', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('download_tokens', schema=None) as batch_op:
        batch_op.drop_column('user_groups')
