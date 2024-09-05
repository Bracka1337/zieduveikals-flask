from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import datetime
import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from flask_migrate import Migrate
from sqlalchemy import Enum
import enum

DATABASE_URL = os.getenv("POSTGRES_URL")
REFRESH_TOKEN_SECRET = os.getenv("REFRESH_TOKEN_SECRET")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
CORS(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


class Role(enum.Enum):
    ADMIN = "ADMIN"
    USER = "USER"
    GUEST = "GUEST"


class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str]
    password: Mapped[str] 
    refresh_token: Mapped[str] = mapped_column(nullable=True)
    role: Mapped[Role] = mapped_column(Enum(Role, native_enum=True), default=Role.USER)


class Product(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    price: Mapped[float]
    quantity: Mapped[int]
    photo: Mapped[str]
    description: Mapped[str]




@app.route('/register', methods=['POST'])
def register(): 
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not username or not email or not password:
        return jsonify({'message': 'Username, email, and password are required'}), 400
    
    user = db.session.query(User).filter_by(username=username).first()

    if user:
        return jsonify({'message': 'Username already exists'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    db.session.add(User(username=username, email=email, password=hashed_password, role=Role.USER))
    db.session.commit()

    return jsonify({'status': 'success'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400
    
    user = db.session.query(User).filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        refresh_token = jwt.encode({
            'sub': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, REFRESH_TOKEN_SECRET, algorithm='HS256')


        
        db.session.query(User).filter_by(username=username).update({'refresh_token': refresh_token})

        db.session.commit()


        access_token = jwt.encode({
            'sub': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
        }, ACCESS_TOKEN_SECRET, algorithm='HS256')

        return jsonify({'refresh_token': refresh_token, 'access_token': access_token})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401
    
@app.route('/refresh', methods=['POST'])
def refresh():
    data = request.json
    refresh_token = data.get('refresh_token')

    if not refresh_token:
        return jsonify({'message': 'Refresh token is required'}), 400

    try:
        decoded_token = jwt.decode(refresh_token, REFRESH_TOKEN_SECRET, algorithms=['HS256'])
        username = decoded_token['sub']
        user = db.session.query(User).filter_by(username=username).first()

        if user and user.refresh_token == refresh_token:
            access_token = jwt.encode({
                'sub': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
            }, ACCESS_TOKEN_SECRET, algorithm='HS256')


            refresh_token = jwt.encode({
                'sub': username,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, REFRESH_TOKEN_SECRET, algorithm='HS256')

            db.session.query(User).filter_by(username=username).update({'refresh_token': refresh_token})

            db.session.commit()

            return jsonify({'access_token': access_token, 'refresh_token': refresh_token})
        else:
            return jsonify({'message': 'Invalid refresh token'}), 401
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Invalid refresh token'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid refresh token'}), 401
    

@app.route('/get_product/<int:id>', methods=['GET'])
def get_product(id):
    product = db.session.query(Product).filter_by(id=id).first()
    if product:
        return jsonify({
            'id': product.id,
            'name': product.name,
            'price': product.price,
            'quantity': product.quantity,
            'photo': product.photo,
            'description': product.description
        })
    else:
        return jsonify({'message': 'Product not found'}), 404
    

@app.route('/get_products', methods=['GET'])
def get_products():
    products = db.session.query(Product).all()
    product_list = [
        {'id': p.id, 'name': p.name, 'price': p.price, 'quantity': p.quantity, 'photo': p.photo, 'description': p.description}
        for p in products
    ]
    return jsonify({'products': product_list})
    


@app.route('/get_users', methods=['GET'])
def get_users():
    token = request.headers.get('Authorization')
    if token:
        token = token.split(' ')[1]
        try:
            decoded_token = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=['HS256'])
            username = decoded_token['sub']
            user = db.session.query(User).filter_by(username=username).first()
            if user.role == Role.ADMIN:
                users = db.session.query(User).filter(User.id != user.id).all()
                user_list = [{'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role.value} for u in users]
                return jsonify({'users': user_list})
            else:
                return jsonify({'message': 'Unauthorized'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Unauthorized'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Unauthorized'}), 401
    else:
         return jsonify({'message': 'Unauthorized'}), 401


# @app.route('/products', methods=['GET', 'POST'])
# def manage_products():
#     if request.method == 'GET':
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute('SELECT id, name, price, quantity, photo, description FROM products')
#         products = cursor.fetchall()
#         cursor.close()
#         conn.close()

#         product_list = [
#             {'id': prod[0], 'name': prod[1], 'price': float(prod[2]), 'quantity': prod[3], 'photo': prod[4], 'description': prod[5]}
#             for prod in products
#         ]
#         return jsonify({'products': product_list})

#     elif request.method == 'POST':
#         data = request.json
#         name = data.get('name')
#         price = data.get('price')
#         quantity = data.get('quantity')
#         photo = data.get('photo')
#         description = data.get('description', '')  

#         if not name or not price or not quantity:
#             return jsonify({'message': 'Name, price, and quantity are required'}), 400

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute(
#             'INSERT INTO products (name, price, quantity, photo, description) VALUES (%s, %s, %s, %s, %s) RETURNING id',
#             (name, price, quantity, photo, description)
#         )
#         product_id = cursor.fetchone()[0]
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return jsonify({'id': product_id, 'name': name, 'price': float(price), 'quantity': quantity, 'photo': photo, 'description': description}), 201

# @app.route('/products/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
# def manage_product_by_id(id):
#     conn = get_db_connection()
#     cursor = conn.cursor()

#     if request.method == 'GET':
#         cursor.execute('SELECT id, name, price, quantity, photo, description FROM products WHERE id = %s', (id,))
#         product = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if product:
#             product_data = {
#                 'id': product[0],
#                 'name': product[1],
#                 'price': float(product[2]),
#                 'quantity': product[3],
#                 'photo': product[4], 
#                 'description': product[5] 
#             }
#             return jsonify(product_data)
#         else:
#             return jsonify({'message': 'Product not found'}), 404

#     elif request.method == 'PATCH':
#         update_data = request.json
#         set_clause = ', '.join(f"{key} = %s" for key in update_data.keys())
#         values = list(update_data.values()) + [id]

#         cursor.execute(f'UPDATE products SET {set_clause} WHERE id = %s', values)
#         conn.commit()

#         cursor.execute('SELECT id, name, price, quantity, photo, description FROM products WHERE id = %s', (id,))
#         updated_product = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if updated_product:
#             product_data = {
#                 'id': updated_product[0],
#                 'name': updated_product[1],
#                 'price': float(updated_product[2]),
#                 'quantity': updated_product[3],
#                 'photo': updated_product[4], 
#                 'description': updated_product[5]
#             }
#             return jsonify(product_data)
#         else:
#             return jsonify({'message': 'Product not found'}), 404

#     elif request.method == 'DELETE':
#         cursor.execute('DELETE FROM products WHERE id = %s', (id,))
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return '', 204




# @app.route('/promos', methods=['GET', 'POST'])
# def manage_promos():
#     if request.method == 'GET':
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute('SELECT id, code, discount, count_usage FROM promos')
#         promos = cursor.fetchall()
#         cursor.close()
#         conn.close()

#         promo_list = [
#             {'id': promo[0], 'code': promo[1], 'discount': promo[2], 'count_usage': promo[3]}
#             for promo in promos
#         ]
#         return jsonify({'promos': promo_list})

#     elif request.method == 'POST':
#         data = request.json
#         code = data.get('code')
#         discount = data.get('discount')
#         count_usage = data.get('count_usage')

#         if not code or discount is None or count_usage is None:
#             return jsonify({'message': 'Code, discount, and count_usage are required'}), 400

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute(
#             'INSERT INTO promos (code, discount, count_usage) VALUES (%s, %s, %s) RETURNING id',
#             (code, discount, count_usage)
#         )
#         promo_id = cursor.fetchone()[0]
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return jsonify({'id': promo_id, 'code': code, 'discount': discount, 'count_usage': count_usage}), 201

# @app.route('/promos/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
# def manage_promo_by_id(id):
#     conn = get_db_connection()
#     cursor = conn.cursor()

#     if request.method == 'GET':
#         cursor.execute('SELECT id, code, discount, count_usage FROM promos WHERE id = %s', (id,))
#         promo = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if promo:
#             promo_data = {
#                 'id': promo[0],
#                 'code': promo[1],
#                 'discount': promo[2],
#                 'count_usage': promo[3]
#             }
#             return jsonify(promo_data)
#         else:
#             return jsonify({'message': 'Promo not found'}), 404

#     elif request.method == 'PATCH':
#         update_data = request.json
#         set_clause = ', '.join(f"{key} = %s" for key in update_data.keys())
#         values = list(update_data.values()) + [id]

#         cursor.execute(f'UPDATE promos SET {set_clause} WHERE id = %s', values)
#         conn.commit()

#         cursor.execute('SELECT id, code, discount, count_usage FROM promos WHERE id = %s', (id,))
#         updated_promo = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if updated_promo:
#             promo_data = {
#                 'id': updated_promo[0],
#                 'code': updated_promo[1],
#                 'discount': updated_promo[2],
#                 'count_usage': updated_promo[3]
#             }
#             return jsonify(promo_data)
#         else:
#             return jsonify({'message': 'Promo not found'}), 404

#     elif request.method == 'DELETE':
#         cursor.execute('DELETE FROM promos WHERE id = %s', (id,))
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return '', 204

# @app.route('/api/logout', methods=['POST'])
# def logout():
#     token = request.headers.get('Authorization')
#     if token:
#         token = token.split(' ')[1]
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute('UPDATE users SET token = NULL WHERE token = %s', (token,))
#         conn.commit()
#         cursor.close()
#         conn.close()
#         return jsonify({'message': 'Logged out successfully'})
#     else:
#         return jsonify({'message': 'Token is missing'}), 400
    
# @app.route('/orders', methods=['GET', 'POST'])
# def manage_orders():
#     if request.method == 'GET':
#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute('SELECT order_id, user_id, username, selected_item, name, phone_number, amount, created_at FROM orders')
#         orders = cursor.fetchall()
#         cursor.close()
#         conn.close()

#         order_list = [
#             {
#                 'order_id': order[0],
#                 'user_id': order[1],
#                 'username': order[2],
#                 'selected_item': order[3],
#                 'name': order[4],
#                 'phone_number': order[5],
#                 'amount': float(order[6]),
#                 'created_at': order[7].isoformat()
#             }
#             for order in orders
#         ]
#         return jsonify({'orders': order_list})

#     elif request.method == 'POST':
#         data = request.json
#         user_id = data.get('user_id')
#         username = data.get('username')
#         selected_item = data.get('selected_item')
#         name = data.get('name')
#         phone_number = data.get('phone_number', '')
#         amount = data.get('amount')

#         if not user_id or not username or not selected_item or not name or amount is None:
#             return jsonify({'message': 'User ID, username, selected item, name, and amount are required'}), 400

#         conn = get_db_connection()
#         cursor = conn.cursor()
#         cursor.execute(
#             'INSERT INTO orders (user_id, username, selected_item, name, phone_number, amount) VALUES (%s, %s, %s, %s, %s, %s) RETURNING order_id',
#             (user_id, username, selected_item, name, phone_number, amount)
#         )
#         order_id = cursor.fetchone()[0]
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return jsonify({
#             'order_id': order_id,
#             'user_id': user_id,
#             'username': username,
#             'selected_item': selected_item,
#             'name': name,
#             'phone_number': phone_number,
#             'amount': float(amount),
#             'created_at': datetime.datetime.now().isoformat()
#         }), 201

# @app.route('/orders/<int:order_id>', methods=['GET', 'PATCH', 'DELETE'])
# def manage_order_by_id(order_id):
#     conn = get_db_connection()
#     cursor = conn.cursor()

#     if request.method == 'GET':
#         cursor.execute('SELECT order_id, user_id, username, selected_item, name, phone_number, amount, created_at FROM orders WHERE order_id = %s', (order_id,))
#         order = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if order:
#             order_data = {
#                 'order_id': order[0],
#                 'user_id': order[1],
#                 'username': order[2],
#                 'selected_item': order[3],
#                 'name': order[4],
#                 'phone_number': order[5],
#                 'amount': float(order[6]),
#                 'created_at': order[7].isoformat()
#             }
#             return jsonify(order_data)
#         else:
#             return jsonify({'message': 'Order not found'}), 404

#     elif request.method == 'PATCH':
#         update_data = request.json
#         set_clause = ', '.join(f"{key} = %s" for key in update_data.keys())
#         values = list(update_data.values()) + [order_id]

#         if 'created_at' in update_data:
#             values[values.index(update_data['created_at'])] = datetime.datetime.strptime(update_data['created_at'], '%Y-%m-%dT%H:%M:%S.%fZ')

#         cursor.execute(f'UPDATE orders SET {set_clause} WHERE order_id = %s', values)
#         conn.commit()

#         cursor.execute('SELECT order_id, user_id, username, selected_item, name, phone_number, amount, created_at FROM orders WHERE order_id = %s', (order_id,))
#         updated_order = cursor.fetchone()
#         cursor.close()
#         conn.close()

#         if updated_order:
#             order_data = {
#                 'order_id': updated_order[0],
#                 'user_id': updated_order[1],
#                 'username': updated_order[2],
#                 'selected_item': updated_order[3],
#                 'name': updated_order[4],
#                 'phone_number': updated_order[5],
#                 'amount': float(updated_order[6]),
#                 'created_at': updated_order[7].isoformat()
#             }
#             return jsonify(order_data)
#         else:
#             return jsonify({'message': 'Order not found'}), 404

#     elif request.method == 'DELETE':
#         cursor.execute('DELETE FROM orders WHERE order_id = %s', (order_id,))
#         conn.commit()
#         cursor.close()
#         conn.close()

#         return '', 204

# @app.route('/logs', methods=['GET'])
# def get_logs():
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     cursor.execute('SELECT id, log_time, module_name, log_level, username, action FROM logs')
#     logs = cursor.fetchall()
#     cursor.close()
#     conn.close()

#     log_list = [
#         {
#             'id': log[0],
#             'log_time': log[1].isoformat(),
#             'module_name': log[2],
#             'log_level': log[3],
#             'username': log[4],
#             'action': log[5]
#         }
#         for log in logs
#     ]
#     return jsonify({'logs': log_list})

if __name__ == '__main__':
    app.run(debug=True)