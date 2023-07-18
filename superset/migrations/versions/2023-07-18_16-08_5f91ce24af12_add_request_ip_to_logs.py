

revision = "5f91ce24af12"
down_revision = "6d05b0a70c89"

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


def upgrade():
    op.add_column("logs", sa.Column("request_ip", sa.String(512), nullable=True))


def downgrade():
    op.drop_column("logs", "request_id")

