"""Initial migration

Revision ID: 543ac4f63deb
Revises: 
Create Date: 2025-01-11 17:20:39.720076

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '543ac4f63deb'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('domain_rank',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('domain_name', sa.String(length=255), nullable=False),
    sa.Column('rank', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('domain_name')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=150), nullable=False),
    sa.Column('email', sa.String(length=150), nullable=False),
    sa.Column('password', sa.String(length=150), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('phishing_url',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('url', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('flagged', sa.Boolean(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('url',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('long_url', sa.String(length=500), nullable=True),
    sa.Column('short_url', sa.String(length=10), nullable=True),
    sa.Column('custom_url', sa.String(length=50), nullable=True),
    sa.Column('clicks', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('custom_url'),
    sa.UniqueConstraint('short_url')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('url')
    op.drop_table('phishing_url')
    op.drop_table('user')
    op.drop_table('domain_rank')
    # ### end Alembic commands ###
