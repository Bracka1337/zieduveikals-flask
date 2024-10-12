from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import jwt
import datetime
import os
import stripe
import time
import uuid
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column,backref
from flask_migrate import Migrate
from sqlalchemy import Enum
import enum
from dotenv import load_dotenv
from functools import wraps
from flask_swagger_ui import get_swaggerui_blueprint
from stripe.checkout import Session
from flask_mail import Mail, Message
import redis


load_dotenv()

redis_url = os.getenv("REDIS_URL")
r = redis.from_url(redis_url)

REFRESH_TOKEN_SECRET = os.getenv("REFRESH_TOKEN_SECRET")
ACCESS_TOKEN_SECRET = os.getenv("ACCESS_TOKEN_SECRET")
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
REFRESH_PASSWORD_SECRET = os.getenv("REFRESH_PASSWORD_SECRET")
MODE = os.getenv("MODE", "production").lower()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("POSTGRES_URL")
app.config["MAIL_SERVER"] = "sandbox.smtp.mailtrap.io"
app.config["MAIL_PORT"] = 2525
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)
CORS(app, resources={r"/*": {"origins": "*"}})
db = SQLAlchemy(app)
migrate = Migrate(app, db)

swagger_ui_blueprint = get_swaggerui_blueprint(
    "/swagger", "/static/swagger.json", config={"app_name": "ZieduVeikals"}
)
app.register_blueprint(swagger_ui_blueprint, url_prefix="/swagger")

class Role(enum.Enum):
    ADMIN = "ADMIN"
    USER = "USER"

class Flower(enum.Enum):
    FLOWER = "FLOWER"
    BOUQUET = "BOUQUET"

class Status(enum.Enum):
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class OptionType(enum.Enum):
    COLOR = "COLOR"
    SIZE = "SIZE"
    MATERIAL = "MATERIAL"
    OTHER = "OTHER"

class User(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str]
    password: Mapped[str]
    role: Mapped[Role] = mapped_column(
        Enum(Role, native_enum=True), default=Role.USER
    )
    promocode_id: Mapped[int] = mapped_column(
        db.ForeignKey("promocode.id", ondelete='SET NULL'), nullable=True
    )
    current_promocode = db.relationship(
        "Promocode",
        backref=backref("users_with_current_promocode", passive_deletes=True)
    )
    orders = db.relationship(
        "Order",
        backref=backref("user", passive_deletes=True), cascade="all, delete-orphan"
    )
    cart_items = db.relationship(
        "CartItem",
        backref=backref("user", passive_deletes=True), cascade="all, delete-orphan"
    )

class Promocode(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str]
    discount: Mapped[float]
    count_usage: Mapped[int]

class Order(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        db.ForeignKey("user.id", ondelete='CASCADE')
    )
    status: Mapped[Status] = mapped_column(
        Enum(Status, native_enum=True), default=Status.PENDING
    )
    created_at: Mapped[datetime.datetime] = mapped_column(
        default=datetime.datetime.utcnow
    )
    order_id: Mapped[str] = mapped_column(unique=True)
    promocode_id: Mapped[int] = mapped_column(
        db.ForeignKey("promocode.id", ondelete='SET NULL'), nullable=True
    )
    promocode = db.relationship(
        "Promocode",
        backref=backref("orders", passive_deletes=True)
    )
    items = db.relationship(
        "OrderItem",
        backref=backref("order", passive_deletes=True), cascade="all, delete-orphan"
    )
    # 'user' relationship is created via backref from 'User.orders'

# ... [rest of your models with similar adjustments]

class Product(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    price: Mapped[float]
    quantity: Mapped[int]
    short_description: Mapped[str]
    type: Mapped[Flower] = mapped_column(Enum(Flower, native_enum=True))
    options = db.relationship("Option", backref=backref("product", passive_deletes=True), cascade="all, delete-orphan")
    order_items = db.relationship("OrderItem", backref=backref("product", passive_deletes=True), cascade=None)
    cart_items = db.relationship("CartItem", backref=backref("product", passive_deletes=True), cascade="all, delete-orphan")

class Option(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    description: Mapped[str] = mapped_column(nullable=True)
    type: Mapped[OptionType] = mapped_column(Enum(OptionType, native_enum=True))
    product_id: Mapped[int] = mapped_column(db.ForeignKey("product.id", ondelete='CASCADE'))
    images = db.relationship("Image", backref=backref("option", passive_deletes=True), cascade="all, delete-orphan")

class Image(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str]
    option_id: Mapped[int] = mapped_column(db.ForeignKey("option.id", ondelete='CASCADE'))

class OrderItem(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(db.ForeignKey("order.id", ondelete='CASCADE'))
    product_id: Mapped[int] = mapped_column(db.ForeignKey("product.id", ondelete='SET NULL'), nullable=True)
    quantity: Mapped[int]
    price: Mapped[float]
    
    product_name: Mapped[str]  # Store product name in OrderItem
    product_description: Mapped[str] = mapped_column(nullable=True)  # Store product description
    product_photo: Mapped[str] = mapped_column(nullable=True)  # Store product photo



class CartItem(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(db.ForeignKey("user.id", ondelete='CASCADE'))
    product_id: Mapped[int] = mapped_column(db.ForeignKey("product.id", ondelete='CASCADE'))
    quantity: Mapped[int]

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get("Authorization")
            if token:
                try:
                    token = token.split(" ")[1]
                    decoded_token = jwt.decode(
                        token, ACCESS_TOKEN_SECRET, algorithms=["HS256"]
                    )
                    username = decoded_token["sub"]
                    user = db.session.query(User).filter_by(username=username).first()

                    if user and (user.role == role or role == Role.USER):
                        return f(user, *args, **kwargs)
                    else:
                        return jsonify({"message": "Unauthorized"}), 401
                except jwt.ExpiredSignatureError:
                    return jsonify({"message": "Token expired"}), 401
                except jwt.InvalidTokenError:
                    return jsonify({"message": "Invalid token"}), 401
            else:
                return jsonify({"message": "Authorization token is required"}), 401

        return decorated_function

    return decorator

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"message": "Username, email, and password are required"}), 400

    user = db.session.query(User).filter_by(username=username).first()

    if user:
        return jsonify({"message": "Username already exists"}), 400

    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    db.session.add(
        User(username=username, email=email, password=hashed_password, role=Role.USER)
    )
    db.session.commit()

    return jsonify({"status": "success"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    user = db.session.query(User).filter_by(username=username).first()

    if user and bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
        refresh_token = jwt.encode(
            {
                "sub": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            },
            REFRESH_TOKEN_SECRET,
            algorithm="HS256",
        )

        r.setex(f"refresh_token:{username}", 3600, refresh_token)

        access_token = jwt.encode(
            {
                "sub": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
            },
            ACCESS_TOKEN_SECRET,
            algorithm="HS256",
        )

        return jsonify({"refresh_token": refresh_token, "access_token": access_token})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route("/refresh", methods=["POST"])
def refresh():
    data = request.json
    refresh_token = data.get("refresh_token")

    if not refresh_token:
        return jsonify({"message": "Refresh token is required"}), 400

    try:
        decoded_token = jwt.decode(
            refresh_token, REFRESH_TOKEN_SECRET, algorithms=["HS256"]
        )
        username = decoded_token["sub"]

        redis_refresh_token = r.get(f"refresh_token:{username}")
        if not redis_refresh_token or redis_refresh_token.decode('utf-8') != refresh_token:
            return jsonify({"message": "Invalid or expired refresh token"}), 401

        access_token = jwt.encode(
            {
                "sub": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
            },
            ACCESS_TOKEN_SECRET,
            algorithm="HS256",
        )

        new_refresh_token = jwt.encode(
            {
                "sub": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            },
            REFRESH_TOKEN_SECRET,
            algorithm="HS256",
        )

        r.setex(f"refresh_token:{username}", 3600, new_refresh_token)

        return jsonify(
            {"access_token": access_token, "refresh_token": new_refresh_token}
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Expired refresh token"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid refresh token"}), 401

@app.route("/change_password", methods=["PATCH"])
@role_required(Role.USER)
def change_password(user):
    data = request.json
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({"message": "Old password and new password are required"}), 400

    user = db.session.query(User).filter_by(username=user.username).first()

    if bcrypt.checkpw(old_password.encode("utf-8"), user.password.encode("utf-8")):
        hashed_password = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        db.session.query(User).filter_by(username=user.username).update(
            {"password": hashed_password}
        )
        db.session.commit()

        return (
            jsonify({"status": "success", "message": "Password changed successfully"}),
            200,
        )
    else:
        return jsonify({"message": "Invalid old password"}), 400

@app.route("/reset-password", methods=["POST"])
def reset_password():
    data = request.json
    email = data.get("email")

    if not email:
        return jsonify({"message": "Email is required"}), 400

    user = db.session.query(User).filter_by(email=email).first()

    if not user:
        return jsonify({"message": "Email not found"}), 400

    refresh = jwt.encode(
        {
            "sub": user.username,
            "email": user.email,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15),
        },
        REFRESH_PASSWORD_SECRET,
        algorithm="HS256",
    )

    msg = Message(

        "Password Reset",
        sender="from@example.com",
        recipients=[user.email],
        body=f"Click the link to reset your password: {refresh}",
    )

    mail.send(msg)

    return (
        jsonify({"status": "success", "message": "Password reset link sent to email"}),
        200,
    )

@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "GET":
        data = request.args 
        token = data.get("token")

        if not token:
            return jsonify({"message": "Token is required"}), 400

        try:
            decoded_token = jwt.decode(
                token, REFRESH_PASSWORD_SECRET, algorithms=["HS256"]
            )
            email = decoded_token["email"]
            user = db.session.query(User).filter_by(email=email).first()

            if user:
                return jsonify({"status": "success", "message": "Token is valid"}), 200

            return jsonify({"message": "Invalid token"}), 400
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 400
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 400

    elif request.method == "POST":
        data = request.json
        new_password = data.get("password")
        token = data.get("token")

        if not new_password or not token:
            return jsonify({"message": "Password and token are required"}), 400

        try:
            decoded_token = jwt.decode(
                token, REFRESH_PASSWORD_SECRET, algorithms=["HS256"]
            )
            email = decoded_token["email"]
            user = db.session.query(User).filter_by(email=email).first()

            if user:
                hashed_password = bcrypt.hashpw(
                    new_password.encode("utf-8"), bcrypt.gensalt()
                ).decode("utf-8")
                db.session.query(User).filter_by(email=email).update(
                    {"password": hashed_password}
                )
                db.session.commit()
                return (
                    jsonify(
                        {"status": "success", "message": "Password reset successfully"}
                    ),
                    200,
                )

            return jsonify({"message": "Invalid token"}), 400
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 400
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 400

@app.route("/product/<int:id>", methods=["GET", "PATCH", "DELETE"])
def handle_product(id):
    product = db.session.query(Product).filter_by(id=id).first()
    if not product:
        return jsonify({"message": "Product not found"}), 404

    if request.method == "GET":
        product_data = {
            "id": product.id,
            "name": product.name,
            "price": product.price,
            "quantity": product.quantity,
            "short_description": product.short_description,
            "photo": product.photo,
            "description": product.description,
            "type": product.type.value,
            "options": [
                {
                    "id": option.id,
                    "name": option.name,
                    "description": option.description,
                    "type": option.type.value,
                    "images": [image.url for image in option.images],
                }
                for option in product.options
            ],
        }
        return jsonify(product_data), 200

    return modify_or_delete_product(product)

@role_required(Role.ADMIN)
def modify_or_delete_product(user, product):
    if request.method == "PATCH":
        data = request.json

        product.name = data.get("name", product.name)
        product.price = data.get("price", product.price)
        product.quantity = data.get("quantity", product.quantity)
        product.photo = data.get("photo", product.photo)
        product.description = data.get("description", product.description)
        product.short_description = data.get("short_description", product.short_description)
        product_type = data.get("type")
        if product_type:
            try:
                product.type = Flower(product_type)
            except ValueError:
                return jsonify({"message": "Invalid product type"}), 400

        # Handle options if provided
        options_data = data.get("options")
        if options_data:
            for option in options_data:
                option_id = option.get("id")
                if option_id:
                    # Update existing option
                    existing_option = db.session.query(Option).filter_by(id=option_id, product_id=product.id).first()
                    if existing_option:
                        existing_option.name = option.get("name", existing_option.name)
                        existing_option.description = option.get("description", existing_option.description)
                        option_type = option.get("type")
                        if option_type:
                            try:
                                existing_option.type = OptionType(option_type)
                            except ValueError:
                                return jsonify({"message": "Invalid option type"}), 400
                        # Handle images
                        images = option.get("images")
                        if images:
                            # Clear existing images and add new ones
                            existing_option.images = []
                            for img_url in images:
                                existing_option.images.append(Image(url=img_url))
                else:
                    # Create new option
                    new_option = Option(
                        name=option["name"],
                        description=option.get("description"),
                        type=OptionType(option["type"]),
                        product=product
                    )
                    images = option.get("images", [])
                    for img_url in images:
                        new_option.images.append(Image(url=img_url))
                    db.session.add(new_option)

        # Optionally handle deletion of options if needed

        db.session.commit()
        return jsonify({"status": "success", "message": "Product updated"}), 200

    if request.method == "DELETE":
        db.session.delete(product)
        db.session.commit()
        return jsonify({"status": "success", "message": "Product deleted"}), 200

@app.route("/products", methods=["GET", "POST"])
def products():
    if request.method == "GET":
        products = Product.query.all()
        products_data = [
            {
                "id": p.id,
                "name": p.name,
                "price": p.price,
                "quantity": p.quantity,
                "short_description": p.short_description,
                "type": p.type.value,
                "options": [
                    {
                        "id": option.id,
                        "name": option.name,
                        "description": option.description,
                        "type": option.type.value,
                        "images": [image.url for image in option.images],
                    }
                    for option in p.options
                ],
            }
            for p in products
        ]
        return jsonify({"products": products_data}), 200

    return create_product()

@role_required(Role.ADMIN)
def create_product(current_user: User):
    if current_user.role != Role.ADMIN:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    required = {"name", "price", "quantity", "type", "short_description"}
    if not required.issubset(data):
        return (
            jsonify(
                {"message": "Name, price, quantity, and type are required"}
            ),
            400,
        )

    # Validate product type
    try:
        product_type = Flower(data["type"])
    except ValueError:
        return jsonify({"message": "Invalid product type"}), 400

    product = Product(
        name=data["name"],
        price=data["price"],
        quantity=data["quantity"],
        short_description=data["short_description"],
        type=product_type,
    )

    # Handle options if provided
    options_data = data.get("options", [])
    for option in options_data:
        option_name = option.get("name")
        option_type = option.get("type")
        if not option_name or not option_type:
            return jsonify({"message": "Each option must have a name and type"}), 400
        try:
            option_enum = OptionType(option_type)
        except ValueError:
            return jsonify({"message": f"Invalid option type: {option_type}"}), 400

        new_option = Option(
            name=option_name,
            description=option.get("description"),
            type=option_enum,
            product=product
        )
        images = option.get("images", [])
        for img_url in images:
            new_option.images.append(Image(url=img_url))
        db.session.add(new_option)

    db.session.add(product)
    db.session.commit()
    return jsonify({"status": "success"}), 201

@app.route("/get_users", methods=["GET"])
@role_required(Role.ADMIN)
def get_users(user):
    users = db.session.query(User).filter(User.username != user.username).all()
    user_list = []
    for u in users:
        promocode_data = (
            {
                "id": u.current_promocode.id,
                "code": u.current_promocode.code,
                "discount": u.current_promocode.discount,
                "count_usage": u.current_promocode.count_usage,
            }
            if u.current_promocode
            else None
        )

        user_list.append(
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "role": u.role.value,
                "promocode": promocode_data,
            }
        )
    return jsonify({"users": user_list})

def filter_products(products):
    product_ids = [product["id"] for product in products]
    db_products = db.session.query(Product).filter(Product.id.in_(product_ids)).all()
    db_product_dict = {db_product.id: db_product for db_product in db_products}

    total_price = 0.0

    for product in products[:]:
        db_product = db_product_dict.get(product["id"])
        if db_product:
            if db_product.quantity < product["quantity"]:
                product["quantity"] = db_product.quantity
                product["name"] = db_product.name
            if db_product.quantity == 0 or product["quantity"] == 0:
                products.remove(product)
            else:
                total_price += product["quantity"] * db_product.price
        else:
            products.remove(product)

    return {"products": products, "total_price": total_price}

@app.route("/add", methods=["POST"])
@role_required(Role.USER)
def add(user):
    data = request.json
    products = data.get("products")

    if not products:
        return jsonify({"message": "No products provided"}), 400

    filtered = filter_products(products)

    if not filtered["products"]:
        return jsonify({"message": "No products found or product quantity is 0"}), 404

    for product in filtered["products"]:
        product_id = product["id"]
        quantity = product["quantity"]

        cart_item = (
            db.session.query(CartItem)
            .filter_by(user_id=user.id, product_id=product_id)
            .first()
        )

        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(
                user_id=user.id, product_id=product_id, quantity=quantity
            )
            db.session.add(cart_item)

    db.session.commit()

    return (
        jsonify(
            {
                "message": "Products added to cart",
                "total_price": filtered["total_price"],
            }
        ),
        201,
    )

@app.route("/cart", methods=["GET", "DELETE"])
@role_required(Role.USER)
def view_cart(user):
    cart_items = db.session.query(CartItem).filter_by(user_id=user.id).all()
    products = db.session.query(Product).all()
    product_dict = {product.id: product for product in products}

    if request.method == "GET":
        if not cart_items:
            return jsonify({"message": "Cart is empty"}), 200

        serialized_cart_items = []
        for item in cart_items:
            product = product_dict.get(item.product_id)
            if product:
                quantity = min(item.quantity, product.quantity)

                serialized_item = {
                    "id": item.id,
                    "product_id": product.id,
                    "name": product.name,
                    "price": product.price,
                    "photo": product.photo,
                    "quantity": item.quantity,
                    "short_description": product.short_description,
                    "actual_quantity": product.quantity,
                    "message": (
                        "Product quantity updated" if quantity < item.quantity else None
                    ),
                }
                serialized_cart_items.append(serialized_item)
            else:
                db.session.delete(item)

        db.session.commit()

        promocode = (
            {
                "code": user.current_promocode.code,
                "discount": user.current_promocode.discount,
            }
            if user.current_promocode
            else None
        )

        return (
            jsonify({"cart_items": serialized_cart_items, "promocode": promocode}),
            200,
        )

    elif request.method == "DELETE":
        if not cart_items:
            return jsonify({"message": "Cart is already empty"}), 200

        db.session.query(CartItem).filter_by(user_id=user.id).delete()
        db.session.commit()

        return jsonify({"message": "Cart cleared successfully"}), 200

@app.route("/cart/<int:id>", methods=["PATCH", "DELETE"])
@role_required(Role.USER)
def modify_or_delete_cart_item(user, id):
    cart_item = db.session.query(CartItem).filter_by(id=id, user_id=user.id).first()
    if not cart_item:
        return jsonify({"message": "Cart item not found"}), 404

    product = db.session.query(Product).filter_by(id=cart_item.product_id).first()

    if not product:
        return jsonify({"message": "Associated product not found"}), 404


    if request.method == "PATCH":
        data = request.json
        new_quantity = data.get("quantity")

        if new_quantity is None or new_quantity < 1 or (product and product.quantity < new_quantity):
            return jsonify({"message": "Invalid quantity"}), 400

        cart_item.quantity = new_quantity
        db.session.commit()

        return jsonify({"message": "Cart item quantity updated successfully"}), 200

    elif request.method == "DELETE":
        db.session.delete(cart_item)
        db.session.commit()

        return jsonify({"message": "Cart item deleted successfully"}), 200

def count_total_price(cart_items):
    ids = [item.product_id for item in cart_items]
    products = db.session.query(Product).filter(Product.id.in_(ids)).all()
    product_dict = {product.id: product for product in products}

    total_price = 0.0

    new_cart_items = []

    for item in cart_items:
        product = product_dict.get(item.product_id)
        new_item = {}
        if product and product.quantity > 0:
            new_item["product_id"] = product.id
            new_item["quantity"] = min(item.quantity, product.quantity)
            new_item["price"] = product.price
            new_item["name"] = product.name
            total_price += item.quantity * product.price
            new_cart_items.append(new_item)

    return {"total_price": total_price, "products": new_cart_items}


def create_payment_link(filtered, promocode) -> Session:
    line_items = []
    for product in filtered["products"]:
        unit_amount = int(round(product["price"] * 100)) 
        if promocode:
            unit_amount = round(unit_amount * (1 - promocode.discount / 100))
            unit_amount = int(unit_amount)

        line_item = {
            "price_data": {
                "currency": "eur",
                "unit_amount": unit_amount,
                "product_data": {
                    "name": product["name"],
                    # "description": product["description"],
                    # "images": [product["images"][0]] if product["images"] else [],
                },
            },
            "quantity": product["quantity"],
        }
        line_items.append(line_item)

    checkout_session = stripe.checkout.Session.create(
        payment_method_types=["card"],
        line_items=line_items,
        mode="payment",
        success_url=f"https://yourdomain.com/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"https://yourdomain.com/cancel",
        client_reference_id=str(uuid.uuid4()),
        expires_at=int(time.time()) + 2000,
    )
    return checkout_session

@app.route("/buy", methods=["POST"])
@role_required(Role.USER)
def buy(user):
    order_items = db.session.query(CartItem).filter_by(user_id=user.id).all()

    if not order_items:
        return jsonify({"message": "No products found or product quantity is 0"}), 404

    user = db.session.query(User).filter_by(username=user.username).first()

    if (
        db.session.query(Order)
        .filter_by(user_id=user.id, status=Status.PENDING)
        .first()
    ):
        return jsonify({"message": "You have a pending order"}), 400

    filtered = count_total_price(order_items)
    print(filtered)
    if len(filtered["products"]) == 0:
        return jsonify({"message": "No products found or product quantity is 0"}), 404

    res = create_payment_link(filtered, user.current_promocode)

    new_order = Order(user_id=user.id, order_id=res.id)
    new_order.promocode_id = (
        user.current_promocode.id if user.current_promocode else None
    )
    if user.current_promocode:
        user.current_promocode.count_usage -= 1
    user.current_promocode = None
    db.session.add(new_order)
    db.session.commit()

    for product in filtered["products"]:
        db_product = db.session.query(Product).filter_by(id=product["product_id"]).first()
        print(db_product)
        if db_product:
            db_product.quantity -= product["quantity"]
            db.session.add(
                OrderItem(
                    order_id=new_order.id,
                    product_id=product["product_id"],
                    quantity=product["quantity"],
                    price=db_product.price,
                    product_name=db_product.name,  # Save product name
                    #product_description=db_product.description,  # Save product description
                    #product_photo=db_product.photo  # Save product photo
                )
            )


    db.session.commit()

    return jsonify({"payment_link": res.url}), 201

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json
    event_type = data.get("type")
    obj = data["data"]["object"]

    if event_type == "checkout.session.completed":
        if obj["payment_status"] == "paid":
            db.session.query(Order).filter_by(order_id=obj["id"]).update(
                {"status": Status.COMPLETED}
            )
            user_id = (
                db.session.query(Order).filter_by(order_id=obj["id"]).first().user_id
            )
            db.session.query(CartItem).filter_by(user_id=user_id).delete()
            db.session.commit()
        return {"status": "success", "message": "Payment completed."}, 200

    elif event_type == "checkout.session.expired":
        order = db.session.query(Order).filter_by(order_id=obj["id"]).first()
        if order:
            order.status = Status.CANCELLED

            for item in order.items:
                product = (
                    db.session.query(Product).filter_by(id=item.product_id).first()
                )
                if product:
                    product.quantity += item.quantity

            db.session.commit()

        return {
            "status": "success",
            "message": "Order cancelled due to session expiration.",
        }, 200

    return {"status": "error", "message": "Unhandled event type."}, 400

@app.route("/orders", methods=["GET"])
@role_required(Role.USER)
def get_orders(user):
    if user.role == Role.ADMIN:
        orders = db.session.query(Order).all()
    else:
        orders = db.session.query(Order).filter_by(user_id=user.id).all()

    order_list = []
    for order in orders:
        promocode_data = (
            {
                "id": order.promocode.id,
                "code": order.promocode.code,
                "discount": order.promocode.discount,
                "count_usage": order.promocode.count_usage,
            }
            if order.promocode
            else None
        )

        order_data = {
            "id": order.id,
            "status": order.status.value,
            "created_at": order.created_at.isoformat(),
            "user": {
                "id": order.user.id,
                "username": order.user.username,
                "email": order.user.email,
                "role": order.user.role.value,
            },
            "promocode": promocode_data, 
           "items": [
                {
                    "id": item.id,
                    "product_id": item.product_id,  
                    "product_name": item.product_name, 
                    "product_description": item.product_description, 
                    "product_photo": item.product_photo,  
                    "quantity": item.quantity,
                    "price": item.price,
                }
                for item in order.items
            ],
        }
        order_list.append(order_data)

    return jsonify({"orders": order_list}), 200

@app.route("/promocodes", methods=["POST", "GET"])
@role_required(Role.ADMIN)
def promocodes(current_user):
    if request.method == "GET":
        promos = Promocode.query.all()
        return (
            jsonify(
                {
                    "promocodes": [
                        {
                            "id": p.id,
                            "code": p.code,
                            "discount": p.discount,
                            "count_usage": p.count_usage,
                        }
                        for p in promos
                    ]
                }
            ),
            200,
        )

    if request.method == "POST":
        data = request.json
        if not all(k in data for k in ("code", "discount", "count_usage")):
            return (
                jsonify({"message": "Code, discount, and count_usage are required"}),
                400,
            )
        if Promocode.query.filter_by(code=data["code"]).first():
            return jsonify({"message": "Promocode already exists"}), 400
        promo = Promocode(
            code=data["code"],
            discount=data["discount"],
            count_usage=data["count_usage"],
        )
        db.session.add(promo)
        db.session.commit()
        return jsonify({"status": "success"}), 201

@app.route("/promocode/<string:id>", methods=["PATCH", "DELETE", "POST"])
@role_required(Role.USER)
def handle_promocode(user, id):
    if not id:
        if user.current_promocode:
            user.current_promocode.count_usage += 1
        user.current_promocode = None

    promocode = db.session.query(Promocode).filter_by(code=id).first()
    if not promocode:
        return jsonify({"message": "Promocode not found"}), 404

    if request.method == "POST":
        if user.current_promocode:
            user.current_promocode.count_usage += 1

        user.current_promocode = promocode
        promocode.count_usage -= 1
        db.session.commit()
        return jsonify({"status": "success", "message": "Promocode applied"}), 200

    return edit_delete_promocode(promocode, user)

def edit_delete_promocode(promocode, user):
    if user.role != Role.ADMIN:
        return jsonify({"message": "Unauthorized"}), 403

    if request.method == "PATCH":
        data = request.json
        promocode.code = data.get("code", promocode.code)
        promocode.discount = data.get("discount", promocode.discount)
        promocode.count_usage = data.get("count_usage", promocode.count_usage)
        db.session.commit()
        return jsonify({"status": "success", "message": "Promocode updated"}), 200

    if request.method == "DELETE":
        db.session.delete(promocode)
        db.session.commit()
        return jsonify({"status": "success", "message": "Promocode deleted"}), 200

if MODE == "dev":

    @app.route("/make_admin", methods=["POST"])
    @role_required(Role.USER)
    def make_admin(current_user):
        target_user = User.query.filter_by(username=current_user.username).first()
        if not target_user:
            return jsonify({"message": "User not found"}), 404

        target_user.role = Role.ADMIN
        db.session.commit()
        return (
            jsonify(
                {
                    "status": "success",
                    "message": f"User {current_user.username} is now an admin",
                }
            ),
            200,
        )

    print("Development mode enabled: /make_admin route is available.")

if __name__ == "__main__":
    app.run(debug=True)
