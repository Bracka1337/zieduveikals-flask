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
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import aliased


load_dotenv()

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
    "/swagger", "/static/swagger.yaml", config={"app_name": "ZieduVeikals"}
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
    DEFAULT = "DEFAULT"
    COLOR = "COLOR"
    SIZE = "SIZE"

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
        back_populates="users_with_current_promocode",
        passive_deletes=True
    )
    
    orders = db.relationship(
        "Order",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    
    cart_items = db.relationship(
        "CartItem",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True
    )


class Promocode(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str]
    discount: Mapped[float]
    count_usage: Mapped[int]
    
    users_with_current_promocode = db.relationship(
        "User",
        back_populates="current_promocode",
        passive_deletes=True
    )
    
    orders = db.relationship(
        "Order",
        back_populates="promocode",
        passive_deletes=True
    )


class Order(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(db.ForeignKey("user.id", ondelete='CASCADE'))
    status: Mapped[Status] = mapped_column(Enum(Status, native_enum=True), default=Status.PENDING)
    created_at: Mapped[datetime.datetime] = mapped_column(default=datetime.datetime.utcnow)
    order_id: Mapped[str] = mapped_column(unique=True)
    promocode_id: Mapped[int] = mapped_column(db.ForeignKey("promocode.id", ondelete='SET NULL'), nullable=True)
    
    promocode = db.relationship(
        "Promocode",
        back_populates="orders",
        passive_deletes=True
    )
    
    user = db.relationship(
        "User",
        back_populates="orders"
    )
    
    items = db.relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

    

class Product(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    short_description: Mapped[str]
    discount: Mapped[int] = mapped_column(nullable=True)
    is_featured: Mapped[bool] = mapped_column(default=False, nullable=True)
    type: Mapped[Flower] = mapped_column(Enum(Flower, native_enum=True))
    
    options = db.relationship(
        "Option",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    
    order_items = db.relationship(
        "OrderItem",
        back_populates="product",
        cascade=None,
        passive_deletes=True
    )
    
    cart_items = db.relationship(
        "CartItem",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

class Option(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    description: Mapped[str] = mapped_column(nullable=True)
    quantity: Mapped[int]
    price: Mapped[float] = mapped_column(nullable=True)
    type: Mapped[OptionType] = mapped_column(Enum(OptionType, native_enum=True))
    product_id: Mapped[int] = mapped_column(db.ForeignKey("product.id", ondelete='CASCADE'))
    
    product = db.relationship("Product", back_populates="options")
    
    images = db.relationship(
        "Image",
        back_populates="option",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    
    cart_items = db.relationship(
        "CartItem",
        back_populates="selected_option",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

class Image(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    url: Mapped[str]
    option_id: Mapped[int] = mapped_column(db.ForeignKey("option.id", ondelete='CASCADE'))
    
    option = db.relationship("Option", back_populates="images")


class OrderItem(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    order_id: Mapped[int] = mapped_column(db.ForeignKey("order.id", ondelete='CASCADE'))
    product_id: Mapped[int] = mapped_column(db.ForeignKey("product.id", ondelete='SET NULL'), nullable=True)
    quantity: Mapped[int]
    price: Mapped[float]
    
    product_name: Mapped[str] 
    product_description: Mapped[str] = mapped_column(nullable=True) 
    product_photo: Mapped[str] = mapped_column(nullable=True) 
    
    order = db.relationship(
        "Order",
        back_populates="items"
    )
    
    product = db.relationship(
        "Product",
        back_populates="order_items"
    )




class CartItem(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(db.ForeignKey("user.id", ondelete='CASCADE'))
    product_id: Mapped[int] = mapped_column(db.ForeignKey("product.id", ondelete='CASCADE'))
    option_id: Mapped[int] = mapped_column(db.ForeignKey("option.id", ondelete='CASCADE'), nullable=True) 
    quantity: Mapped[int]
    
    selected_option = db.relationship("Option", back_populates="cart_items")
    
    product = db.relationship("Product", back_populates="cart_items")
    
    user = db.relationship("User", back_populates="cart_items")

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
        access_token = jwt.encode(
            {
                "sub": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=365*100),
            },
            ACCESS_TOKEN_SECRET,
            algorithm="HS256",
        )

        return jsonify({"access_token": access_token})
    else:
        return jsonify({"message": "Invalid credentials"}), 401


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
            "short_description": product.short_description,
            "discount": product.discount,
            "photo": product.photo,
            "description": product.description,
            "type": product.type.value,
            "options": [
                {
                    "id": option.id,
                    "name": option.name,
                    "description": option.description,
                    "type": option.type.value,
                    "price": option.price,
                    "quantity": option.quantity,
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
        product.short_description = data.get("short_description", product.short_description)
        product.discount = data.get("discount", product.discount)
        product.is_featured = data.get("is_featured", product.is_featured)

        product_type = data.get("type")
        if product_type:
            try:
                product.type = Flower(product_type)
            except ValueError:
                return jsonify({"message": "Invalid product type"}), 400

        options_to_delete = data.get("options_to_delete", [])
        if options_to_delete:
            if not isinstance(options_to_delete, list):
                return jsonify({"message": "options_to_delete must be a list of option IDs"}), 400
            existing_option_ids = {option.id for option in product.options}
            for option_id in options_to_delete:
                if not isinstance(option_id, int):
                    return jsonify({"message": f"Invalid option ID: {option_id}"}), 400
                if option_id not in existing_option_ids:
                    return jsonify({"message": f"Option ID {option_id} does not exist for this product"}), 400
                
                default_option = db.session.query(Option).filter_by(product_id=product.id, type=OptionType.DEFAULT).first()
                if option_id == default_option.id:
                    return jsonify({"message": "Cannot delete the default option"}), 400
                option_to_remove = db.session.query(Option).filter_by(id=option_id, product_id=product.id).first()
                if option_to_remove:
                    db.session.delete(option_to_remove)

        options_data = data.get("options", [])

        if options_data:
            if not isinstance(options_data, list):
                return jsonify({"message": "Options data must be a list"}), 400

            existing_options = db.session.query(Option).filter_by(product_id=product.id).options(joinedload(Option.images)).all()
            existing_options_dict = {option.id: option for option in existing_options if option.id}

            for option_data in options_data:
                option_id = option_data.get("id")
                if option_id:
                    existing_option = existing_options_dict.get(option_id)
                    if not existing_option:
                        return jsonify({"message": f"Option with ID {option_id} not found"}), 404

                    existing_option.name = option_data.get("name", existing_option.name)
                    existing_option.description = option_data.get("description", existing_option.description)

                    quantity = option_data.get("quantity")
                    if quantity is not None:
                        try:
                            quantity = int(quantity)
                            if quantity < 0:
                                raise ValueError("Quantity must be non-negative.")
                            existing_option.quantity = quantity
                        except ValueError as ve:
                            return jsonify({"message": f"Invalid quantity for option ID {option_id}: {str(ve)}"}), 400

                    price = option_data.get("price")
                    if price is not None:
                        try:
                            price = float(price)
                            if price < 0:
                                raise ValueError("Price must be non-negative.")
                            existing_option.price = price
                        except ValueError as ve:
                            return jsonify({"message": f"Invalid price for option ID {option_id}: {str(ve)}"}), 400

                    option_type = option_data.get("type")
                    if option_type:
                        try:
                            existing_option.type = OptionType(option_type)
                        except ValueError:
                            return jsonify({"message": f"Invalid option type for option ID {option_id}"}), 400

                    images = option_data.get("images")
                    if images is not None:
                        if not isinstance(images, list):
                            return jsonify({"message": f"Images for option ID {option_id} must be a list"}), 400
                        existing_option.images.clear()
                        for img_url in images:
                            if not isinstance(img_url, str):
                                return jsonify({"message": f"Invalid image URL for option ID {option_id}"}), 400
                            new_image = Image(url=img_url)
                            existing_option.images.append(new_image)
                else:
                    try:
                        name = option_data["name"]
                        option_type = option_data["type"]
                        price = option_data["price"]
                        quantity = option_data["quantity"]

                        price = float(price)
                        if price < 0:
                            raise ValueError("Price must be non-negative.")

                        quantity = int(quantity)
                        if quantity < 0:
                            raise ValueError("Quantity must be non-negative.")

                        new_option = Option(
                            name=name,
                            description=option_data.get("description"),
                            type=OptionType(option_type),
                            price=price,
                            quantity=quantity,
                            product=product
                        )
                    except KeyError as e:
                        return jsonify({"message": f"Missing required field: {str(e)}"}), 400
                    except ValueError as ve:
                        return jsonify({"message": f"Invalid value: {str(ve)}"}), 400

                    images = option_data.get("images", [])
                    if not isinstance(images, list):
                        return jsonify({"message": "Images must be a list"}), 400
                    for img_url in images:
                        if not isinstance(img_url, str):
                            return jsonify({"message": "Image URLs must be strings"}), 400
                        new_image = Image(url=img_url)
                        new_option.images.append(new_image)

                    db.session.add(new_option)

        try:
            db.session.commit()
            db.session.refresh(product)
            product_data = {
                "id": product.id,
                "name": product.name,
                "short_description": product.short_description,
                "discount": product.discount,
                "is_featured": product.is_featured,
                "type": product.type.value,
                "options": [
                    {
                        "id": option.id,
                        "name": option.name,
                        "description": option.description,
                        "price": option.price,
                        "quantity": option.quantity,
                        "type": option.type.value,
                        "images": [image.url for image in option.images],
                    }
                    for option in product.options
                ],
            }
            return jsonify({"status": "success", "message": "Product updated", "product": product_data}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error updating product {product.id}: {e}")
            return jsonify({"message": "An error occurred while updating the product."}), 500

    elif request.method == "DELETE":
        try:
            db.session.delete(product)
            db.session.commit()
            return jsonify({"status": "success", "message": "Product deleted"}), 200
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting product {product.id}: {e}")
            return jsonify({"message": "An error occurred while deleting the product."}), 500

    else:
        return jsonify({"message": "Method not allowed"}), 405


@app.route("/products", methods=["GET", "POST"])
def products():
    if request.method == "GET":
        filters = []
        
        int_fields = ['id', 'discount']
        float_fields = [] 
        str_fields = ['name', 'short_description']
        bool_fields = ['is_featured']
        enum_fields = ['type']

        for field in int_fields:
            value = request.args.get(field)
            if value is not None:
                try:
                    int_value = int(value)
                    filters.append(getattr(Product, field) == int_value)
                except ValueError:
                    return jsonify({"error": f"Invalid value for {field}"}), 400

            min_value = request.args.get(f"{field}_min")
            max_value = request.args.get(f"{field}_max")
            if min_value is not None:
                try:
                    min_int_value = int(min_value)
                    filters.append(getattr(Product, field) >= min_int_value)
                except ValueError:
                    return jsonify({"error": f"Invalid min value for {field}"}), 400
            if max_value is not None:
                try:
                    max_int_value = int(max_value)
                    filters.append(getattr(Product, field) <= max_int_value)
                except ValueError:
                    return jsonify({"error": f"Invalid max value for {field}"}), 400

        for field in str_fields:
            value = request.args.get(field)
            if value:
                filters.append(getattr(Product, field).ilike(f"%{value}%"))

        for field in bool_fields:
            value = request.args.get(field)
            if value is not None:
                if value.lower() in ['true', '1']:
                    filters.append(getattr(Product, field).is_(True))
                elif value.lower() in ['false', '0']:
                    filters.append(getattr(Product, field).is_(False))
                else:
                    return jsonify({"error": f"Invalid boolean value for {field}"}), 400

        for field in enum_fields:
            value = request.args.get(field)
            if value:
                try:
                    enum_value = Flower(value)
                    filters.append(getattr(Product, field) == enum_value)
                except ValueError:
                    return jsonify({"error": f"Invalid enum value for {field}"}), 400

        price = request.args.get('price')
        price_min = request.args.get('price_min')
        price_max = request.args.get('price_max')
        quantity = request.args.get('quantity')
        quantity_min = request.args.get('quantity_min')
        quantity_max = request.args.get('quantity_max')

        DefaultOption = aliased(Option)

        query = db.session.query(Product, DefaultOption).outerjoin(
            DefaultOption,
            (DefaultOption.product_id == Product.id) & (DefaultOption.type == OptionType.DEFAULT)
        )

        if filters:
            query = query.filter(*filters)

        if price is not None:
            try:
                price = float(price)
                query = query.filter(DefaultOption.price == price)
            except ValueError:
                return jsonify({"error": "Invalid value for price"}), 400

        if price_min is not None:
            try:
                price_min = float(price_min)
                query = query.filter(DefaultOption.price >= price_min)
            except ValueError:
                return jsonify({"error": "Invalid min value for price"}), 400

        if price_max is not None:
            try:
                price_max = float(price_max)
                query = query.filter(DefaultOption.price <= price_max)
            except ValueError:
                return jsonify({"error": "Invalid max value for price"}), 400

        if quantity is not None:
            try:
                quantity = int(quantity)
                query = query.filter(DefaultOption.quantity == quantity)
            except ValueError:
                return jsonify({"error": "Invalid value for quantity"}), 400

        if quantity_min is not None:
            try:
                quantity_min = int(quantity_min)
                query = query.filter(DefaultOption.quantity >= quantity_min)
            except ValueError:
                return jsonify({"error": "Invalid min value for quantity"}), 400

        if quantity_max is not None:
            try:
                quantity_max = int(quantity_max)
                query = query.filter(DefaultOption.quantity <= quantity_max)
            except ValueError:
                return jsonify({"error": "Invalid max value for quantity"}), 400

        limit = request.args.get('limit')
        offset = request.args.get('offset')
        if limit is not None:
            try:
                limit = int(limit)
                query = query.limit(limit)
            except ValueError:
                return jsonify({"error": "Invalid value for limit"}), 400
        if offset is not None:
            try:
                offset = int(offset)
                query = query.offset(offset)
            except ValueError:
                return jsonify({"error": "Invalid value for offset"}), 400

        results = query.all()

        products_data = []
        for product, default_option in results:
            if not default_option:
                continue  

            product_dict = {
                "id": product.id,
                "name": product.name,
                "short_description": product.short_description,
                "discount": product.discount,
                "type": product.type.value,
                "is_featured": product.is_featured,
                "options": [
                    {
                        "id": option.id,
                        "name": option.name,
                        "description": option.description,
                        "type": option.type.value,
                        "price": option.price,
                        "quantity": option.quantity,
                        "images": [image.url for image in option.images],
                    }
                    for option in product.options
                ],
            }
            products_data.append(product_dict)

        return jsonify({"products": products_data}), 200

    return create_product()


@role_required(Role.ADMIN)
def create_product(current_user: User):
    if current_user.role != Role.ADMIN:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.json
    required = {"name", "type", "short_description"}
    if not required.issubset(data):
        return (
            jsonify(
                {"message": "Name, short description and type are required"}
            ),
            400,
        )

    try:
        product_type = Flower(data["type"])
    except ValueError:
        return jsonify({"message": "Invalid product type"}), 400


    

    product = Product(
        name=data["name"],
        short_description=data["short_description"],
        type=product_type,
    )

    options_data = data.get("options", [])

    if not options_data:
        return jsonify({"message": "At least default option is required"}), 400


    default_option = next((option for option in options_data if option.get("type") == "DEFAULT"), None)
    if not default_option:
        return jsonify({"message": "Default option is required"}), 400

    for option in options_data:
        option_name = option.get("name")
        option_type = option.get("type")
        if not option_name or not option_type:
            return jsonify({"message": "Each option must have a name and type"}), 400
        try:
            option_enum = OptionType(option_type)
        except ValueError:
            return jsonify({"message": f"Invalid option type: {option_type}"}), 400

        if option_enum == OptionType.DEFAULT:
            option_price = option.get("price")
            if option_price is None:
                return jsonify({"message": "Price is required for DEFAULT option type"}), 400
        else:
            option_price = option.get("price") 

        new_option = Option(
            name=option_name,
            description=option.get("description"),
            type=option_enum,
            quantity=option.get("quantity", 0),
            price=option_price,  
            product=product
        )
        images = option.get("images", [])
        for img_url in images:
            new_option.images.append(Image(url=img_url))
        db.session.add(new_option)

    db.session.add(product)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating product: {e}")
        return jsonify({"message": "An error occurred while creating the product."}), 500

    product_data = {
        "id": product.id,
        "name": product.name,
        "short_description": product.short_description,
        "discount": product.discount,
        "is_featured": product.is_featured,
        "type": product.type.value,
        "options": [
            {
                "id": option.id,
                "name": option.name,
                "description": option.description,
                "quantity": option.quantity,
                "type": option.type.value,
                "price": option.price, 
                "images": [image.url for image in option.images],
            }
            for option in product.options
        ],
    }

    return jsonify({"status": "success", "product": product_data}), 201




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

@app.route("/is_admin", methods=["GET"])
@role_required(Role.ADMIN)
def is_admin(user):
    return jsonify({"message": "User is an admin"}), 200



@app.route("/user/<int:user_id>", methods=["GET", "PATCH", "DELETE"])
@role_required(Role.ADMIN)
def handle_user(current_user, user_id):
    user = db.session.query(User).filter_by(id=user_id).first()
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    if request.method == "GET":
        promocode_data = (
            {
                "id": user.current_promocode.id,
                "code": user.current_promocode.code,
                "discount": user.current_promocode.discount,
                "count_usage": user.current_promocode.count_usage,
            }
            if user.current_promocode
            else None
        )
        
        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "promocode": promocode_data,
        }
        return jsonify({"user": user_data}), 200

    elif request.method == "PATCH":
        data = request.json
        allowed_fields = {"username", "email", "role", "promocode_id"}
        update_data = {k: v for k, v in data.items() if k in allowed_fields}

        if not update_data:
            return jsonify({"message": "No valid fields to update"}), 400

        if "role" in update_data:
            try:
                update_data["role"] = Role(update_data["role"])
            except ValueError:
                return jsonify({"message": "Invalid role specified"}), 400

        if "promocode_id" in update_data:
            if update_data["promocode_id"] is not None:
                promocode = db.session.query(Promocode).filter_by(id=update_data["promocode_id"]).first()
                if not promocode:
                    return jsonify({"message": "Promocode not found"}), 404
            else:
                update_data["promocode_id"] = None

        try:
            for key, value in update_data.items():
                setattr(user, key, value)
            db.session.commit()
            return jsonify({"status": "success", "message": "User updated successfully"}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating user {user_id}: {e}")
            return jsonify({"message": "An error occurred while updating the user."}), 500

    elif request.method == "DELETE":
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({"status": "success", "message": "User deleted successfully"}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting user {user_id}: {e}")
            return jsonify({"message": "An error occurred while deleting the user."}), 500

    else:
        return jsonify({"message": "Method not allowed"}), 405

def filter_products(products, user):
    total_price = 0.0
    filtered_products = []
    
    for product in products:
        product_id = product.get("id")
        quantity_requested = product.get("quantity", 1)
        option_id = product.get("option_id")

        db_product = db.session.query(Product).filter_by(id=product_id).first()
        if not db_product:
            continue 

        if option_id:
            db_option = db.session.query(Option).filter_by(id=option_id, product_id=product_id).first()
            if not db_option:
                continue  
        else:
            db_option = db.session.query(Option).filter_by(product_id=product_id, type=OptionType.DEFAULT).first()
            if not db_option:
                continue 

        if db_option.quantity < quantity_requested:
            quantity_available = db_option.quantity
            if quantity_available == 0:
                continue  
            quantity_requested = quantity_available  

        discount_factor = 1.0
        if db_product.discount is not None:
            discount_factor *= (1 - (db_product.discount / 100))


        price = 0

        if db_option.price is None:
            price = db.session.query(Option).filter_by(product_id=product_id, type=OptionType.DEFAULT).first().price
        else:
            price = db_option.price
            
     

        if user.current_promocode:
            discount_factor *= (1 - (user.current_promocode.discount / 100))

        line_total = quantity_requested * price * discount_factor
        total_price += line_total

        filtered_products.append({
            "id": product_id,
            "name": db_product.name,
            "quantity": quantity_requested,
            "option_id": db_option.id,
            "price": price,
            "discount_factor": discount_factor
        })

    return {"products": filtered_products, "total_price": round(total_price, 2)}


    

@app.route("/add", methods=["POST"])
@role_required(Role.USER)
def add(user):
    data = request.json
    products = data.get("products")

    if not products:
        return jsonify({"message": "No products provided"}), 400

    filtered = filter_products(products, user)

    if not filtered["products"]:
        return jsonify({"message": "No products found or product quantity is 0"}), 404

    for product in filtered["products"]:
        product_id = product["id"]
        quantity = product["quantity"]
        option_id = product.get("option_id")

        db_option = db.session.query(Option).filter_by(id=option_id, product_id=product_id).first()
        if not db_option:
            return jsonify({"message": f"Invalid option_id {option_id} for product_id {product_id}"}), 400

        cart_item = (
            db.session.query(CartItem)
            .filter_by(user_id=user.id, product_id=product_id, option_id=option_id)
            .first()
        )

        if cart_item:
            cart_item.quantity += quantity
        else:
            cart_item = CartItem(
                user_id=user.id,
                product_id=product_id,
                option_id=option_id,
                quantity=quantity
            )
            db.session.add(cart_item)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "An error occurred while adding products to the cart."}), 500

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
    
    if request.method == "GET":
        if not cart_items:
            return jsonify({"message": "Cart is empty"}), 200

        serialized_cart_items = []
        total_price = 0.0
        adjustments_made = False  

        for item in cart_items:
            product = item.product
            option = item.selected_option  

            if not product:
                db.session.delete(item)
                adjustments_made = True
                continue

            if option:
                available_quantity = option.quantity
                price_per_unit = option.price
            else:
                default_option = db.session.query(Option).filter_by(product_id=product.id, type=OptionType.DEFAULT).first()
                if not default_option:
                    db.session.delete(item)
                    adjustments_made = True
                    continue
                available_quantity = default_option.quantity
                price_per_unit = default_option.price
                option = default_option 
            
            if price_per_unit is None:
                default_option = db.session.query(Option).filter_by(product_id=product.id, type=OptionType.DEFAULT).first()
                price_per_unit = default_option.price
            

            if available_quantity < item.quantity:
                if available_quantity == 0:
                    db.session.delete(item)
                    adjustments_made = True
                    continue
                else:
                    original_quantity = item.quantity
                    item.quantity = available_quantity
                    adjustments_made = True
                    message = "Product quantity updated due to limited stock"
            else:
                message = None

            discount_factor = 1.0
            if product.discount is not None:
                discount_factor *= (1 - (product.discount / 100))
            if user.current_promocode:
                discount_factor *= (1 - (user.current_promocode.discount / 100))

            

            line_total = item.quantity * price_per_unit * discount_factor
            total_price += line_total

            serialized_item = {
                "id": item.id,
                "product_id": product.id,
                "name": product.name,
                "price_per_unit": round(price_per_unit, 2),
                "quantity": item.quantity,
                "discount_factor": round(discount_factor, 2),
                "line_total": round(line_total, 2),
                "short_description": product.short_description,
                "selected_option": {
                    "id": option.id,
                    "name": option.name,
                    "type": option.type.value,
                    "price": round(price_per_unit, 2),
                    "quantity_available": option.quantity,
                    "images": [image.url for image in option.images],
                } if option else None,
                "message": message,
            }
            serialized_cart_items.append(serialized_item)

        if adjustments_made:
            db.session.commit()

        promocode = (
            {
                "code": user.current_promocode.code,
                "discount": user.current_promocode.discount,
            }
            if user.current_promocode
            else None
        )

        return jsonify({
            "cart_items": serialized_cart_items,
            "total_price": round(total_price, 2),
            "promocode": promocode
        }), 200

    elif request.method == "DELETE":
        if not cart_items:
            return jsonify({"message": "Cart is already empty"}), 200

        try:
            for item in cart_items:
                option = item.selected_option
                if option:
                    option.quantity += item.quantity
                else:
                    default_option = db.session.query(Option).filter_by(product_id=item.product_id, type=OptionType.DEFAULT).first()
                    if default_option:
                        default_option.quantity += item.quantity

            db.session.query(CartItem).filter_by(user_id=user.id).delete()
            db.session.commit()

            return jsonify({"message": "Cart cleared successfully"}), 200

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error clearing cart for user {user.id}: {e}")
            return jsonify({"message": "An error occurred while clearing the cart."}), 500

    else:
        return jsonify({"message": "Method not allowed"}), 405

@app.route("/cart/<int:id>", methods=["PATCH", "DELETE"])
@role_required(Role.USER)
def modify_or_delete_cart_item(user, id):
    cart_item = db.session.query(CartItem).filter_by(id=id, user_id=user.id).first()
    if not cart_item:
        return jsonify({"message": "Cart item not found"}), 404

    product = db.session.query(Product).filter_by(id=cart_item.product_id).first()

    if not product:
        return jsonify({"message": "Associated product not found"}), 404

    if cart_item.option_id:
        option = db.session.query(Option).filter_by(id=cart_item.option_id, product_id=product.id).first()
        if not option:
            return jsonify({"message": "Associated option not found"}), 404
    else:
        option = db.session.query(Option).filter_by(product_id=product.id, type=OptionType.DEFAULT).first()
        if not option:
            return jsonify({"message": "Default option not found for the product."}), 404

    if request.method == "PATCH":
        data = request.json
        new_quantity = data.get("quantity")

        if new_quantity is None or not isinstance(new_quantity, int) or new_quantity < 1:
            return jsonify({"message": "Quantity must be a positive integer."}), 400

        quantity_diff = new_quantity - cart_item.quantity

        if quantity_diff > 0:
            if option.quantity < quantity_diff:
                return jsonify({"message": "Insufficient stock for the selected option.", "max": option.quantity}), 400
        elif quantity_diff < 0:
            pass 

        cart_item.quantity = new_quantity

        try:
            db.session.commit()
            return jsonify({"message": "Cart item quantity updated successfully."}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error updating cart item {id}: {e}")
            return jsonify({"message": "An error occurred while updating the cart item."}), 500

    elif request.method == "DELETE":
        try:
            db.session.delete(cart_item)
            db.session.commit()
            return jsonify({"message": "Cart item deleted successfully."}), 200
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error deleting cart item {id}: {e}")
            return jsonify({"message": "An error occurred while deleting the cart item."}), 500


def count_total_price(cart_items, customer_status):
   
    total_price = 0.0
    new_cart_items = []

    for item in cart_items:
        product = item.product
        option = item.selected_option if item.option_id else db.session.query(Option).filter_by(product_id=product.id, type=OptionType.DEFAULT).first()

        if not option:
            continue  

        if option.quantity <= 0:
            continue

        adjusted_quantity = min(item.quantity, option.quantity)

        if adjusted_quantity <= 0:
            continue 


        price = option.price

        if price is None:
            price = db.session.query(Option).filter_by(product_id=product.id, type=OptionType.DEFAULT).first().price

        price_per_unit = price if customer_status == "fiz" else price * 0.79

        discount_factor = 1.0
        if product.discount is not None:
            discount_factor *= (1 - (product.discount / 100))

        if customer_status == "promocode" and user.current_promocode:
            discount_factor *= (1 - (user.current_promocode.discount / 100))

        line_total = adjusted_quantity * price_per_unit * discount_factor
        total_price += line_total

        new_cart_items.append({
            "product_id": product.id,
            "option_id": option.id,
            "quantity": adjusted_quantity,
            "price": price_per_unit,
            "name": product.name,
            "discount": product.discount
        })

    return {"total_price": round(total_price, 2), "products": new_cart_items}



def create_payment_link(filtered, promocode) -> Session:
   
    line_items = []
    for product in filtered["products"]:
        option_id = product.get("option_id")
        if option_id:
            option = db.session.query(Option).filter_by(id=option_id).first()
            if not option:
                continue
            unit_price = option.price
            option_details = f" - {option.name}"  
        else:
            option = db.session.query(Option).filter_by(product_id=product["product_id"], type=OptionType.DEFAULT).first()
            if not option:
                continue
            unit_price = option.price
            option_details = ""

        if unit_price is None:
            unit_price = db.session.query(Option).filter_by(product_id=product["product_id"], type=OptionType.DEFAULT).first().price

        if product["discount"]:
            unit_price *= (1 - product["discount"] / 100)

        if promocode:
            unit_price *= (1 - promocode.discount / 100)

        unit_amount = int(round(unit_price * 100))

        product_name = f"{product['name']}{option_details}"

        if option.images and len(option.images) > 0:
            first_image_url = option.images[0].url
            images = [first_image_url]
        else:
            images = []

        line_item = {
            "price_data": {
                "currency": "eur",
                "unit_amount": unit_amount,
                "product_data": {
                    "name": product_name,
                    "images": images,  
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

    if db.session.query(Order).filter_by(user_id=user.id, status=Status.PENDING).first():
        return jsonify({"message": "You have a pending order"}), 400

    data = request.json

    customer_status = data.get("customer_status") 

    filtered = count_total_price(order_items, customer_status)
    print(filtered)  

    if len(filtered["products"]) == 0:
        return jsonify({"message": "No products found or product quantity is 0"}), 404

    res = create_payment_link(filtered, user.current_promocode)

    new_order = Order(user_id=user.id, order_id=res.id, status=Status.PENDING)
    new_order.promocode_id = user.current_promocode.id if user.current_promocode else None

    if user.current_promocode:
        user.current_promocode.count_usage -= 1
        if user.current_promocode.count_usage < 0:
            user.current_promocode.count_usage = 0

    user.current_promocode = None 

    db.session.add(new_order)
    db.session.commit()

    for product in filtered["products"]:
        db_product = db.session.query(Product).filter_by(id=product["product_id"]).first()
        if not db_product:
            continue 

        option_id = product.get("option_id")
        option = db.session.query(Option).filter_by(id=option_id).first() if option_id else None

        price = option.price

        if price is None:
            price = db.session.query(Option).filter_by(product_id=product["product_id"], type=OptionType.DEFAULT).first().price


        if product.get("discount"):
            price *= (1 - product["discount"] / 100)

        if user.current_promocode:
            price *= (1 - user.current_promocode.discount / 100)

        order_item = OrderItem(
            order_id=new_order.id,
            product_id=product["product_id"],
            quantity=product["quantity"],
            price=round(price, 2), 
            product_name=db_product.name,
            product_description=db_product.short_description, 
            product_photo=option.images[0].url if option and option.images else None, 
        )
        db.session.add(order_item)

        if option:
            option.quantity -= product["quantity"]
            if option.quantity < 0:
                option.quantity = 0 
        else:
            default_option = db.session.query(Option).filter_by(product_id=db_product.id, type=OptionType.DEFAULT).first()
            if default_option:
                default_option.quantity -= product["quantity"]
                if default_option.quantity < 0:
                    default_option.quantity = 0

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating order for user {user.id}: {e}")
        return jsonify({"message": "An error occurred while processing your order."}), 500

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
        return jsonify({"status": "success", "code": data["code"], "discount": data["discount"], "count_usage": data["count_usage"]}), 201

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
        return jsonify({
            "status": "success",
            "message": "Promocode updated",
                "id": promocode.id,
                "code": promocode.code,
                "discount": promocode.discount,
                "count_usage": promocode.count_usage
        }), 200

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
