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
from dotenv import load_dotenv
from functools import wraps


load_dotenv()


DATABASE_URL = os.getenv("POSTGRES_URL")
REFRESH_TOKEN_SECRET = os.getenv("REFRESH_TOKEN_SECRET")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
CORS(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

from flask_swagger_ui import get_swaggerui_blueprint

SWAGGER_URL="/swagger"
API_URL="/static/swagger.json"

swagger_ui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': 'ZieduVeikals'
    }
)
app.register_blueprint(swagger_ui_blueprint, url_prefix=SWAGGER_URL)

class Role(enum.Enum):
    ADMIN = "ADMIN"
    USER = "USER"
    GUEST = "GUEST"


class Flower(enum.Enum):
    FLOWER = "FLOWER"
    BOUQUET = "BOUQUET"


class Status(enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"

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
    photo: Mapped[str] = mapped_column(nullable=True)
    description: Mapped[str] = mapped_column(nullable=True)
    type: Mapped[Flower] = mapped_column(Enum(Flower, native_enum=True))


class Order(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(db.ForeignKey('user.id'))
    status: Mapped[Status] = mapped_column(Enum(Status, native_enum=True), default=Status.PENDING)
    created_at: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)
    user = db.relationship('User', backref='orders')


class OrderItem(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(db.ForeignKey('order.id'))
    product_id: Mapped[int] = mapped_column(db.ForeignKey('product.id'))
    quantity: Mapped[int]
    price: Mapped[float] 

    order = db.relationship('Order', backref='items')
    product = db.relationship('Product')

class Promocode(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str]
    discount: Mapped[float]
    count_usage: Mapped[int]


class CartItem(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(db.ForeignKey('user.id'))
    product_id: Mapped[int] = mapped_column(db.ForeignKey('product.id'))
    quantity: Mapped[int]

    user = db.relationship('User', backref='cart_items')
    product = db.relationship('Product')





def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.split(' ')[1]
            try:
                decoded_token = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=['HS256'])
                username = decoded_token['sub']
                user = db.session.query(User).filter_by(username=username).first()

                if user and user.role == Role.ADMIN:
                    return f(user, *args, **kwargs)
                else:
                    return jsonify({'message': 'Unauthorized'}), 401
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Unauthorized'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Unauthorized'}), 401
        else:
            return jsonify({'message': 'Unauthorized'}), 401
    return decorated_function


def user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if token:
            token = token.split(' ')[1]
            try:
                decoded_token = jwt.decode(token, ACCESS_TOKEN_SECRET, algorithms=['HS256'])
                username = decoded_token['sub']
                user = db.session.query(User).filter_by(username=username).first()

                if user:
                    return f(user, *args, **kwargs)
                else:
                    return jsonify({'message': 'Unauthorized'}), 401
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token'}), 401
        else:
            return jsonify({'message': 'Authorization token is required'}), 401
    return decorated_function





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
    

@app.route('/create_product', methods=['POST'])
@admin_required
def create_product(user):
    data = request.json
    name = data.get('name')
    price = data.get('price')
    quantity = data.get('quantity')
    photo = data.get('photo')
    description = data.get('description', '')
    flower = data.get('flower')

    if not name or not price or not quantity or not flower:
        return jsonify({'message': 'Name, price, type, and quantity are required'}), 400

    db.session.add(Product(name=name, price=price, quantity=quantity, photo=photo, description=description, type=flower))
    db.session.commit()

    return jsonify({'status': 'success'}), 201


@app.route('/product/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
def handle_product(id):
    product = db.session.query(Product).filter_by(id=id).first()
    if not product:
        return jsonify({'message': 'Product not found'}), 404

    if request.method == 'GET':
        return jsonify({
            'id': product.id,
            'name': product.name,
            'price': product.price,
            'quantity': product.quantity,
            'photo': product.photo,
            'description': product.description
        })

    return modify_or_delete_product(product)

@admin_required
def modify_or_delete_product(product):
    if request.method == 'PATCH':
        data = request.json
        product.name = data.get('name', product.name)
        product.price = data.get('price', product.price)
        product.quantity = data.get('quantity', product.quantity)
        product.photo = data.get('photo', product.photo)
        product.description = data.get('description', product.description)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Product updated'}), 200

    if request.method == 'DELETE':
        db.session.delete(product)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Product deleted'}), 200



@app.route('/get_products', methods=['GET'])
def get_products():
    products = db.session.query(Product).all()
    product_list = [
        {'id': p.id, 'name': p.name, 'price': p.price, 'quantity': p.quantity, 'photo': p.photo, 'description': p.description}
        for p in products
    ]
    return jsonify({'products': product_list})
    


@app.route('/get_users', methods=['GET'])
@admin_required
def get_users(user):
    users = db.session.query(User).filter(User.username != user.username).all()
    user_list = [{'id': u.id, 'username': u.username, 'email': u.email, 'role': u.role.value} for u in users]
    return jsonify({'users': user_list})



def filter_products(products):
    product_ids = [product['id'] for product in products]
    db_products = db.session.query(Product).filter(Product.id.in_(product_ids)).all()
    db_product_dict = {db_product.id: db_product for db_product in db_products}

    total_price = 0.0

    for product in products[:]:
        db_product = db_product_dict.get(product['id'])
        if db_product:
            if db_product.quantity < product['quantity']:
                product['quantity'] = db_product.quantity
            if db_product.quantity == 0 or product['quantity'] == 0:
                products.remove(product)
            else:
                total_price += product['quantity'] * db_product.price
        else:
            products.remove(product)

    return {'products': products, 'total_price': total_price}



@app.route('/add', methods=['POST'])
@user_required
def add(user):
    data = request.json
    products = data.get('products')

    if not products:
        return jsonify({'message': 'No products provided'}), 400

    # Filter and validate the products
    filtered = filter_products(products)

    if not filtered['products']:
        return jsonify({'message': 'No products found or product quantity is 0'}), 404

    # Add filtered products to the user's cart
    for product in filtered['products']:
        product_id = product['id']
        quantity = product['quantity']

        cart_item = db.session.query(CartItem).filter_by(user_id=user.id, product_id=product_id).first()

        if cart_item:
            # Update the quantity if the product is already in the cart
            cart_item.quantity += quantity
        else:
            # Add a new item to the cart
            cart_item = CartItem(user_id=user.id, product_id=product_id, quantity=quantity)
            db.session.add(cart_item)

    db.session.commit()

    return jsonify({'message': 'Products added to cart', 'total_price': filtered['total_price']}), 201



@app.route('/cart', methods=['GET', 'DELETE'])
@user_required
def view_cart(user):
    cart_items = db.session.query(CartItem).filter_by(user_id=user.id).all()

    if request.method == 'GET':
        if not cart_items:
            return jsonify({'message': 'Cart is empty'}), 200

        cart_details = [{
            'id': item.id,
            'product_id': item.product_id,
            'product_name': item.product.name,
            'price': item.product.price,
            'quantity': item.quantity
        } for item in cart_items]

        return jsonify({'cart_items': cart_details}), 200

    elif request.method == 'DELETE':
        if not cart_items:
            return jsonify({'message': 'Cart is already empty'}), 200

        # Clear the cart by deleting all items for the user
        db.session.query(CartItem).filter_by(user_id=user.id).delete()
        db.session.commit()

        return jsonify({'message': 'Cart cleared successfully'}), 200



@app.route('/cart/<int:id>', methods=['PATCH', 'DELETE'])
@user_required
def modify_or_delete_cart_item(user, id):
    # Query for the specific cart item by id and user_id
    cart_item = db.session.query(CartItem).filter_by(id=id, user_id=user.id).first()

    if not cart_item:
        return jsonify({'message': 'Cart item not found'}), 404

    if request.method == 'PATCH':
        data = request.json
        new_quantity = data.get('quantity')

        if new_quantity is None or new_quantity < 1:
            return jsonify({'message': 'Invalid quantity'}), 400

        # Update the quantity of the cart item
        cart_item.quantity = new_quantity
        db.session.commit()

        return jsonify({'message': 'Cart item quantity updated successfully'}), 200

    elif request.method == 'DELETE':
        # Remove the cart item from the database
        db.session.delete(cart_item)
        db.session.commit()

        return jsonify({'message': 'Cart item deleted successfully'}), 200



@app.route('/buy', methods=['POST'])
@user_required
def buy(user):
    data = request.json
    order_items = data.get('order')

    filtered = filter_products(order_items)

    if not filtered['products']:
        return jsonify({'message': 'No products found or product quantity is 0'}), 404

    user = db.session.query(User).filter_by(username=user.username).first()

    new_order = Order(user_id=user.id)
    db.session.add(new_order)
    db.session.commit()  

    for product in filtered['products']:
        db.session.add(OrderItem(
            order_id=new_order.id,
            product_id=product['id'],
            quantity=product['quantity'],
            price=db.session.query(Product).filter_by(id=product['id']).first().price
        ))

    db.session.commit()

    filtered['payment_link'] = "/pay"
    return jsonify(filtered), 201


@app.route('/orders', methods=['GET'])
@user_required
def get_orders(user):

    if user.role == Role.ADMIN:
        orders = db.session.query(Order).all()
    else:
        orders = db.session.query(Order).filter_by(user_id=user.id).all()

    order_list = []
    for order in orders:
        order_data = {
            'id': order.id,
            'status': order.status.value,
            'created_at': order.created_at.isoformat(),
            'user': {
                'id': order.user.id,
                'username': order.user.username,
                'email': order.user.email,
                'role': order.user.role.value
            },
            'items': [
                {
                    'id': item.id,
                    'product_id': item.product_id,
                    'product_name': item.product.name,
                    'quantity': item.quantity,
                    'price': item.price
                }
                for item in order.items
            ]
        }
        order_list.append(order_data)
    
    return jsonify({'orders': order_list}), 200



@app.route('/create_promocode', methods=['POST'])
@admin_required
def create_promocode(user):
    data = request.json
    code = data.get('code')
    discount = data.get('discount')
    count_usage = data.get('count_usage')

    if not code or discount is None or count_usage is None:
        return jsonify({'message': 'Code, discount, and count_usage are required'}), 400

    db.session.add(Promocode(code=code, discount=discount, count_usage=count_usage))
    db.session.commit()

    return jsonify({'status': 'success'}), 201



@app.route('/promocodes', methods=['GET'])
@admin_required
def get_promocodes(user):
    promocodes = db.session.query(Promocode).all()
    promocode_list = [{'id': p.id, 'code': p.code, 'discount': p.discount, 'count_usage': p.count_usage} for p in promocodes]
    return jsonify({'promocodes': promocode_list})



@app.route('/promocode/<int:id>', methods=['PATCH', 'DELETE'])
@admin_required
def handle_promocode(user, id):
    promocode = db.session.query(Promocode).filter_by(id=id).first()
    if not promocode:
        return jsonify({'message': 'Promocode not found'}), 404

    if request.method == 'PATCH':
        data = request.json
        promocode.code = data.get('code', promocode.code)
        promocode.discount = data.get('discount', promocode.discount)
        promocode.count_usage = data.get('count_usage', promocode.count_usage)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Promocode updated'}), 200

    if request.method == 'DELETE':
        db.session.delete(promocode)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Promocode deleted'}), 200




    

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