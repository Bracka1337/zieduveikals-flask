"""promos

Revision ID: 2a07bc1371b5
Revises: a2db8566c009
Create Date: 2024-09-14 23:38:57.646176

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2a07bc1371b5'
down_revision = 'a2db8566c009'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('promocode_id', sa.Integer(), nullable=True))
        batch_op.drop_constraint('user_current_promocode_id_fkey', type_='foreignkey')
        batch_op.create_foreign_key(None, 'promocode', ['promocode_id'], ['id'])
        batch_op.drop_column('current_promocode_id')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('current_promocode_id', sa.INTEGER(), autoincrement=False, nullable=True))
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.create_foreign_key('user_current_promocode_id_fkey', 'promocode', ['current_promocode_id'], ['id'])
        batch_op.drop_column('promocode_id')

    # ### end Alembic commands ###
