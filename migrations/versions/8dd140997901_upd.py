"""upd

Revision ID: 8dd140997901
Revises: 3cb60facea71
Create Date: 2024-09-26 20:06:37.353218

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8dd140997901'
down_revision = '3cb60facea71'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('order_item', schema=None) as batch_op:
        batch_op.drop_constraint('order_item_product_id_fkey', type_='foreignkey')
        batch_op.drop_column('product_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('order_item', schema=None) as batch_op:
        batch_op.add_column(sa.Column('product_id', sa.INTEGER(), autoincrement=False, nullable=True))
        batch_op.create_foreign_key('order_item_product_id_fkey', 'product', ['product_id'], ['id'], ondelete='SET NULL')

    # ### end Alembic commands ###