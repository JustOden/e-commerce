import os
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, FloatField, IntegerField, TextAreaField, FileField
from wtforms.validators import InputRequired, InputRequired, Optional
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user

ITEMS_UPLOAD_PATH = "static/assets/items"
USERS_UPLOAD_PATH = "static/assets/users"
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

app = Flask(__name__)
app.config["ITEMS_UPLOAD_PATH"] = ITEMS_UPLOAD_PATH
app.config["USERS_UPLOAD_PATH"] = USERS_UPLOAD_PATH
app.secret_key = "1234"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///e-commerce.sqlite3"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.permanent_session_lifetime = timedelta(days=31)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


def main():
    with app.app_context():
        db.create_all()
    app.run(debug=True)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, user_id)


def allowed_file(filename):
    return "." in filename and \
           filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired()])
    email = EmailField("Email", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    confirm = PasswordField("Confirm Password", validators=[InputRequired()])
    submit = SubmitField("Register")


class EditUserForm(FlaskForm):
    image = FileField("Image", validators=[Optional(True)])
    name = StringField("Name", validators=[Optional(True)])
    email = EmailField("Email", validators=[Optional(True)])
    old_pw = PasswordField("Old Password", validators=[Optional(True)])
    new_pw = PasswordField("New Password", validators=[Optional(True)])
    confirm = PasswordField("Confirm", validators=[Optional(True)])
    submit = SubmitField("Update")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[InputRequired()])
    password = PasswordField("Password", validators=[InputRequired()])
    submit = SubmitField("Log In")


class AddItemForm(FlaskForm):
    image = FileField("Image", validators=[Optional(True)])
    name = StringField("Name", validators=[InputRequired()])
    price = FloatField("Price", validators=[InputRequired()])
    in_stock = IntegerField("In Stock", validators=[Optional(True)])
    description = TextAreaField("Description", validators=[Optional(True)])
    submit = SubmitField("Add Item")


class UpdateItemForm(FlaskForm):
    image = FileField("Update Image", validators=[Optional(True)])
    name = StringField("Enter Item Name", validators=[InputRequired()])
    price = FloatField("Update Price", validators=[Optional(True)])
    in_stock = IntegerField("Update In Stock", validators=[Optional(True)])
    description = TextAreaField("Update Description", validators=[Optional(True)])
    submit = SubmitField("Update Item")


class DeleteItemForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired()])
    submit = SubmitField("Delete Item")


class Admins(db.Model):
    __tablename__ = "admin"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Users(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(162), nullable=False)
    image_path = db.Column(db.String(150), unique=True)
    image_name = db.Column(db.String(20), unique=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def change_password(self, old_pw: str, new_pw: str) -> None:
        if self.check_password(old_pw):
            self.set_password(new_pw)
            
    def is_admin(self) -> Admins | None:
        return db.session.query(Admins).filter_by(user_id=self.id).first()

    def set_admin(self) -> None:
        new_admin = Admins(user_id=self.id)
        db.session.add(new_admin)

    def remove_admin(self) -> None:
        if client:=self.is_admin():
            db.session.delete(client)


class Items(db.Model):
    __tablename__ = "item"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    in_stock = db.Column(db.Integer, nullable=False)
    description = db.Column(db.Text(255))
    image_path = db.Column(db.String(150), unique=True)
    image_name = db.Column(db.String(20), unique=True)

    def increment_by(self, amount: int) -> None:
        self.in_stock+=amount

    def decrement_by(self, amount: int) -> None:
        self.in_stock-=amount


class Cart(db.Model):
    __tablename__ = "cart"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    user = db.relationship("Users", backref=db.backref("user", uselist=False))
    item = db.relationship("Items", backref=db.backref("item", uselist=False))
    amount_to_buy = db.Column(db.Integer, nullable=False)


def process_cart():
    if current_user.is_authenticated:
        cart_items = db.session.query(Cart).filter_by(user_id=current_user.id).all()
        session["total"] = int(sum([i.item.price*i.amount_to_buy for i in cart_items]))
    else:
        if "anon_cart" in session:
            cart_items = [
                (found_item, int(atb))
                for id, atb in session["anon_cart"].items()
                if (found_item:=db.session.query(Items).filter_by(id=id).first())
            ]
            session["total"] = int(sum([i[0].price*i[1] for i in cart_items]))
        else:
            cart_items = {}
    return cart_items


@app.route("/")
@app.route("/home", methods=["POST", "GET"])
def index():
    search = request.form.get("search")
    all_items = db.session.query(Items).all()
    session["cached_item"] = [(item.name, item.description) for item in all_items]
    if search:
        all_items = [
            item for item in all_items
            if search.lower() in item.name.lower() or
            item.name.lower() in search.lower()
            ]
    cart_items = process_cart()
    if "anon_cart" in session:
        cart_items = {item.id: atb for item, atb in cart_items}
    return render_template("index.html", all_items=all_items, cart_items=cart_items)


@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        confirm = form.confirm.data
        if db.session.query(Users).filter_by(email=email).first():
            flash("User already exists!")
        else:
            if password == confirm:
                client = Users(name=name, email=email)
                client.set_password(password)
                db.session.add(client)
                db.session.commit()
                flash("Account created! Log into your new account!")
                return redirect(url_for("login"))
            else:
                flash("Password does not match. Please retry.")
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        found_user = db.session.query(Users).filter_by(email=email).first()
        if found_user and found_user.check_password(password):
            login_user(found_user)
            if not session.permanent:
                session.permanent = True
            if "anon_cart" in session:
                session.pop("anon_cart", None)
            if "total" in session:
                session.pop("total", None)
            flash("Login successful!")
            return redirect(url_for("index"))
        else:
            flash("Password or Email is incorrect")
    if current_user.is_authenticated:
        flash("Already Logged In!")
        return redirect(url_for("dashboard"))
    else:
        return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    if "anon_cart" in session:
        session.pop("anon_cart", None)
    if "total" in session:
        session.pop("total", None)
    flash("You have been logged out")
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["POST", "GET"])
@login_required
def dashboard():
    form = EditUserForm()
    if form.validate_on_submit():
        image = form.image.data
        name = form.name.data
        email = form.email.data
        old_pw = form.old_pw.data
        new_pw = form.new_pw.data
        confirm = form.confirm.data
        if found_user:=db.session.query(Users).filter_by(id=current_user.id).first():
            if image and allowed_file(image.filename):
                if (path:=found_user.image_path) and os.path.exists(path):
                    os.remove(path)
                filename = secure_filename(image.filename)
                to_path = os.path.join(app.config["USERS_UPLOAD_PATH"], filename)
                image.save(to_path)
                found_user.image_path = to_path
                found_user.image_name = filename
                flash("image changed successfully")
            if name:
                found_user.name = name
                flash("name changed successfully")
            if email:
                found_user.email = email
                flash("email changed successfully")
            if old_pw and new_pw and new_pw == confirm:
                found_user.change_password(old_pw, new_pw)
                flash("password changed successfully")
            db.session.commit()
    return render_template("dashboard.html", form=form)


@app.route("/delete-account")
@login_required
def delete_account():
    if current_user.is_authenticated:
        found_user = db.session.query(Users).filter_by(id=current_user.id).first()
        cart_items = db.session.query(Cart).filter_by(user_id=current_user.id).all()
        for i in cart_items:
            db.session.delete(i)
        db.session.delete(found_user)
        db.session.commit()
        if (path:=found_user.image_path) and os.path.exists(path):
            os.remove(path)
        flash("Your account has been deleted successfully")
    return redirect(url_for("logout"))


@app.route("/cart")
def cart():
    cart_items = process_cart()
    if "anon_cart" in session:
        cart_ids = {item.id: atb for item, atb in cart_items}
    else:
        cart_ids = {}
    return render_template("cart.html", cart_items=cart_items, cart_ids=cart_ids)


@app.route("/cash-out")
def cash_out():
  if current_user.is_authenticated:
      cart_items = process_cart()
      for cart in cart_items:
          cart.item.decrement_by(cart.amount_to_buy)
          flash(f"you have bought {cart.amount_to_buy} {cart.item.name} for ${cart.item.price*cart.amount_to_buy}")
          db.session.delete(cart)
      db.session.commit()
      flash(f"you have spent ${session.get('total')} dollars in total")
  else:
      if "anon_cart" in session:
          cart_items = process_cart()
          for item, atb in cart_items.copy():
              item.decrement_by(atb)
              flash(f"you have bought {atb} {item.name} for ${item.price*atb}")
              session["anon_cart"].pop(str(item.id), None)
          db.session.commit()
          flash(f"you have spent ${session.get('total')} dollars")
  return redirect(url_for("cart"))


@app.route("/process", methods=["POST"])
def process():
    data = request.get_json()
    item = data["item"]
    item_id = int(item[0])
    amount_to_buy = int(item[1])
    if current_user.is_authenticated:
        found_items = db.session.query(Cart).filter_by(user_id=current_user.id).all()
        found_items_dict = {i.item.id:i for i in found_items}
        if item_id not in found_items_dict.keys():
            cart_item = Cart(user_id=current_user.id, item_id=item_id, amount_to_buy=amount_to_buy)
            db.session.add(cart_item)
            flash("New Item Added Successfully.")
        else:
            if (this:=found_items_dict[item_id]).amount_to_buy != amount_to_buy:
                this.amount_to_buy = amount_to_buy
                flash("Existing Item Updated Successfully.")
        updated_items = process_cart()
        updated_items_dict = {i.item.id:i for i in updated_items}
        item_name = updated_items_dict[item_id].item.name
        amount_to_buy = updated_items_dict[item_id].amount_to_buy
        if amount_to_buy == 0:
            db.session.delete(updated_items_dict[item_id])
        db.session.commit()
    else:
        session["anon_cart"] = data["cart"]
        if not session.permanent:
            session.permanent = True
        anon_cart = {item[0].id:item[0] for item in process_cart()}
        item_name = anon_cart[item_id].name if item_id in anon_cart.keys() else ""
        for key, val in (session["anon_cart"].copy()).items():
            if int(val) == 0:
                session["anon_cart"].pop(key, None)
    return jsonify(result=(item_name, amount_to_buy, session.get("total")))


@app.route("/search", methods=["POST"])
def search():
    all_items = [item.name for item in db.session.query(Items).all()]
    return jsonify(result=all_items)


@app.route("/add_item", methods=["POST", "GET"])
@login_required
def add_item():
    form = AddItemForm()
    if form.validate_on_submit():
        image = form.image.data
        name = form.name.data
        price = form.price.data
        in_stock = form.in_stock.data
        description = form.description.data
        if db.session.query(Items).filter_by(name=name).first():
            flash("Item already in database. Please update the price or amount in stock instead")
        else:
            item = Items(name=name, price=price)
            item.in_stock = 0 if not in_stock else in_stock
            if description and len(description) <= 255:
                item.description = description
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                to_path = os.path.join(app.config["ITEMS_UPLOAD_PATH"], filename)
                image.save(to_path)
                item.image_path = to_path
                item.image_name = filename
            db.session.add(item)
            db.session.commit()
            flash("Successfully inserted new item")
    return render_template("add_item.html", form=form, values=db.session.query(Items).all())


@app.route("/update_item", methods=["POST", "GET"])
@login_required
def update_item():
    form = UpdateItemForm()
    if form.validate_on_submit():
        image = form.image.data
        name = form.name.data
        price = form.price.data
        in_stock = form.in_stock.data
        description = form.description.data
        if item:=db.session.query(Items).filter_by(name=name).first():
            if price:
                item.price = price
                flash("Successfully updated price of item")
            if in_stock:
                item.increment_by(in_stock)
                flash("Successfully updated amount of items in stock")
            if description and len(description) <= 255:
                item.description = description
                flash("Successfully updated description of item")
            if image and allowed_file(image.filename):
                if (path:=item.image_path) and os.path.exists(path):
                    os.remove(path)
                filename = secure_filename(image.filename)
                to_path = os.path.join(app.config["ITEMS_UPLOAD_PATH"], filename)
                image.save(to_path)
                item.image_path = to_path
                item.image_name = filename
                flash("Successfully updated image of item")
            db.session.commit()
        else:
            flash("Item doesn't exist")
    return render_template("update_item.html", form=form)


@app.route("/delete_item", methods=["POST", "GET"])
@login_required
def delete_item():
    form = DeleteItemForm()
    if form.validate_on_submit():
        name = form.name.data
        if item:=db.session.query(Items).filter_by(name=name).first():
            if cart_items:=db.session.query(Cart).filter_by(item_id=item.id).all():
                for i in cart_items:
                    db.session.delete(i)
            db.session.delete(item)
            db.session.commit()
            if (path:=item.image_path) and os.path.exists(path):
                os.remove(path)
            flash("Successfully deleted item")
        else:
            flash("Item doesn't exist")
    return render_template("delete_item.html", form=form)


@app.route("/set-admin")
def set_admin():
    if current_user.is_authenticated:
        found_user = db.session.query(Users).filter_by(id=current_user.id).first()
        found_user.set_admin()
        db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/remove-admin")
def remove_admin():
    if current_user.is_authenticated:
        found_user = db.session.query(Users).filter_by(id=current_user.id).first()
        found_user.remove_admin()
        db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/view-users")
def view_users():
    if current_user.is_authenticated and current_user.is_admin():
        return render_template("view_users.html", values=db.session.query(Users).all())
    else:
        return redirect(url_for("index"))


if __name__ == "__main__":
    main()
