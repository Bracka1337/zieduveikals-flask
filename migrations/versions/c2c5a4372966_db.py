"""db

Revision ID: c2c5a4372966
Revises: 
Create Date: 2024-10-12 10:41:22.232296

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c2c5a4372966'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('product',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('price', sa.Float(), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('short_description', sa.String(), nullable=False),
    sa.Column('discount', sa.Integer(), nullable=True),
    sa.Column('type', sa.Enum('FLOWER', 'BOUQUET', name='flower'), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('promocode',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(), nullable=False),
    sa.Column('discount', sa.Float(), nullable=False),
    sa.Column('count_usage', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('option',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('description', sa.String(), nullable=True),
    sa.Column('type', sa.Enum('COLOR', 'SIZE', 'MATERIAL', 'OTHER', name='optiontype'), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['product_id'], ['product.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(), nullable=False),
    sa.Column('email', sa.String(), nullable=False),
    sa.Column('password', sa.String(), nullable=False),
    sa.Column('role', sa.Enum('ADMIN', 'USER', name='role'), nullable=False),
    sa.Column('promocode_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['promocode_id'], ['promocode.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('username')
    )
    op.create_table('cart_item',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=False),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['product_id'], ['product.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('image',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('url', sa.String(), nullable=False),
    sa.Column('option_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['option_id'], ['option.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('order',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.Enum('PENDING', 'COMPLETED', 'CANCELLED', name='status'), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('order_id', sa.String(), nullable=False),
    sa.Column('promocode_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['promocode_id'], ['promocode.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('order_id')
    )
    op.create_table('order_item',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('order_id', sa.Integer(), nullable=False),
    sa.Column('product_id', sa.Integer(), nullable=True),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('price', sa.Float(), nullable=False),
    sa.Column('product_name', sa.String(), nullable=False),
    sa.Column('product_description', sa.String(), nullable=True),
    sa.Column('product_photo', sa.String(), nullable=True),
    sa.ForeignKeyConstraint(['order_id'], ['order.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['product_id'], ['product.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('order_item')
    op.drop_table('order')
    op.drop_table('image')
    op.drop_table('cart_item')
    op.drop_table('user')
    op.drop_table('option')
    op.drop_table('promocode')
    op.drop_table('product')
    # ### end Alembic commands ###