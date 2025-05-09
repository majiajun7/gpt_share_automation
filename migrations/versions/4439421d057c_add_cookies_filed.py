"""add cookies filed

Revision ID: 4439421d057c
Revises: bf524feae85c
Create Date: 2025-04-26 20:01:00.634169

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4439421d057c'
down_revision = 'bf524feae85c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('adspower_accounts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cookies', sa.Text(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('adspower_accounts', schema=None) as batch_op:
        batch_op.drop_column('cookies')

    # ### end Alembic commands ###
