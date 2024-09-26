"""cascade

Revision ID: 595461535f72
Revises: 1e0a7232968f
Create Date: 2024-09-25 12:46:27.702683

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '595461535f72'
down_revision = '1e0a7232968f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('cart_item', schema=None) as batch_op:
        batch_op.drop_constraint('cart_item_product_id_fkey', type_='foreignkey')
        batch_op.drop_constraint('cart_item_user_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'product', ['product_id'], ['id'], ondelete='CASCADE')
        batch_op.create_foreign_key(None, 'user', ['user_id'], ['id'], ondelete='CASCADE')

    with op.batch_alter_table('image', schema=None) as batch_op:
        batch_op.drop_constraint('image_option_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'option', ['option_id'], ['id'], ondelete='CASCADE')

    with op.batch_alter_table('option', schema=None) as batch_op:
        batch_op.drop_constraint('option_product_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'product', ['product_id'], ['id'], ondelete='CASCADE')

    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.drop_constraint('order_user_id_fkey', type_='foreignkey')
        batch_op.drop_constraint('order_promocode_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'user', ['user_id'], ['id'], ondelete='CASCADE')
        batch_op.create_foreign_key(None, 'promocode', ['promocode_id'], ['id'], ondelete='SET NULL')

    with op.batch_alter_table('order_item', schema=None) as batch_op:
        batch_op.drop_constraint('order_item_order_id_fkey', type_='foreignkey')
        batch_op.drop_constraint('order_item_product_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'product', ['product_id'], ['id'], ondelete='CASCADE')
        batch_op.create_foreign_key(None, 'order', ['order_id'], ['id'], ondelete='CASCADE')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('user_promocode_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'promocode', ['promocode_id'], ['id'], ondelete='SET NULL')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('user_promocode_id_fkey', 'promocode', ['promocode_id'], ['id'])

    with op.batch_alter_table('order_item', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('order_item_product_id_fkey', 'product', ['product_id'], ['id'])
        batch_op.create_foreign_key('order_item_order_id_fkey', 'order', ['order_id'], ['id'])

    with op.batch_alter_table('order', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('order_promocode_id_fkey', 'promocode', ['promocode_id'], ['id'])
        batch_op.create_foreign_key('order_user_id_fkey', 'user', ['user_id'], ['id'])

    with op.batch_alter_table('option', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('option_product_id_fkey', 'product', ['product_id'], ['id'])

    with op.batch_alter_table('image', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('image_option_id_fkey', 'option', ['option_id'], ['id'])

    with op.batch_alter_table('cart_item', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('cart_item_user_id_fkey', 'user', ['user_id'], ['id'])
        batch_op.create_foreign_key('cart_item_product_id_fkey', 'product', ['product_id'], ['id'])

    # ### end Alembic commands ###
