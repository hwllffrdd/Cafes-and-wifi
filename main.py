from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Boolean, Float
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SelectField, DecimalField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, NumberRange


class AddCafeForm(FlaskForm):
    name = StringField("Cafe Name", validators=[DataRequired()])
    map_url = StringField("Map URL", validators=[DataRequired(), URL()])
    img_url = StringField("Cafe Image URL", validators=[DataRequired(), URL()])
    location = StringField("Cafe Location", validators=[DataRequired()])
    has_sockets = BooleanField("Has Sockets")
    has_toilets = BooleanField("Has Toilet")
    has_wifi = BooleanField("Has WiFi")
    can_take_calls = BooleanField("Can Take Calls")
    seats = SelectField(
        "Seats",
        choices=[
            ("0-10", "Few (0-10)"),
            ("10-20", "Some (10-20)"),
            ("20-30", "Many (20-30)"),
            ("30-40", "Lots (30-40)"),
            ("40-50", "Lots and lots (40-50)"),
            ("50+", "Lots and lots and lots (50+)")
        ],
        validators=[DataRequired()]
    )
    coffee_price = DecimalField(
        "Coffee Price",
        validators=[DataRequired(), NumberRange(min=0.01, message="Price must be at least 0.01")],
        places=2
    )
    submit = SubmitField("Submit Cafe")


class RegisterForm(FlaskForm):
    email = StringField("E-mail", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


app = Flask(__name__)
app.config['SECRET_KEY'] = '86e0e42950d370e309153250ee03f9fadbcff62afc45ec7a'
ckeditor = CKEditor(app)
Bootstrap5(app)


class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cafes.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


class Cafe(db.Model):
    __tablename__ = "cafe"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    map_url: Mapped[str] = mapped_column(String(500), nullable=False)
    img_url: Mapped[str] = mapped_column(String(500), nullable=False)
    location: Mapped[str] = mapped_column(String(250), nullable=False)
    has_sockets: Mapped[bool] = mapped_column(Boolean, nullable=False)
    has_toilet: Mapped[bool] = mapped_column(Boolean, nullable=False)
    has_wifi: Mapped[bool] = mapped_column(Boolean, nullable=False)
    can_take_calls: Mapped[bool] = mapped_column(Boolean, nullable=False)
    seats: Mapped[str] = mapped_column(String(250), nullable=True)
    coffee_price: Mapped[float] = mapped_column(Float, nullable=True)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(100))


with app.app_context():
    db.create_all()


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        new_email = register_form.email.data
        result = db.session.execute(db.select(User).where(User.email == new_email))
        existing_user = result.scalar()
        if existing_user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8)

        new_user = User(email=register_form.email.data, name=register_form.name.data, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("cafes"))
    return render_template("register.html", form=register_form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        logging_user = login_form.email.data
        logging_password = login_form.password.data
        result = db.session.execute(db.select(User).where(User.email == logging_user))
        registered_user = result.scalar()
        if not registered_user:
            flash('That email does not exist in our database, please try again.')
            return redirect(url_for('login'))

        elif not check_password_hash(registered_user.password, logging_password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))

        else:
            login_user(registered_user)
            return redirect(url_for('cafes'))

    return render_template("login.html", form=login_form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('cafes'))


@app.route('/')
def cafes():
    result = db.session.execute(db.select(Cafe))
    all_cafes = result.scalars().all()
    return render_template("index.html", all_cafes=all_cafes)


@app.route("/new-cafe", methods=["GET", "POST"])
def add_new_cafe():
    form = AddCafeForm()
    if form.validate_on_submit():
        new_cafe = Cafe(
            name=form.name.data,
            map_url=form.map_url.data,
            img_url=form.img_url.data,
            location=form.location.data,
            has_sockets=form.has_sockets.data,
            has_toilet=form.has_toilets.data,
            has_wifi=form.has_wifi.data,
            can_take_calls=form.can_take_calls.data,
            seats=form.seats.data,
            coffee_price=float(form.coffee_price.data)
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for("cafes"))
    return render_template("add_cafe.html", form=form, current_user=current_user)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route("/edit-cafe/<int:cafe_id>", methods=["GET", "POST"])
@admin_only
def edit_cafe(cafe_id):
    cafe = db.get_or_404(Cafe, cafe_id)
    edit_form = AddCafeForm(
        name=cafe.name,
        map_url=cafe.map_url,
        img_url=cafe.img_url,
        location=cafe.location,
        has_sockets=cafe.has_sockets,
        has_toilet=cafe.has_toilets,
        has_wifi=cafe.has_wifi,
        can_take_calls=cafe.can_take_calls,
        seats=cafe.seats,
        coffee_price=cafe.coffee_price
    )
    if edit_form.validate_on_submit():
        cafe.name = edit_form.name.data,
        cafe.map_url = edit_form.map_url.data,
        cafe.img_url = edit_form.img_url.data,
        cafe.location = edit_form.location.data,
        cafe.has_sockets = edit_form.has_sockets.data,
        cafe.has_toilet = edit_form.has_toilets.data,
        cafe.has_wifi = edit_form.has_wifi.data,
        cafe.can_take_calls = edit_form.can_take_calls.data,
        cafe.seats = edit_form.seats.data,
        cafe.coffee_price = edit_form.coffee_price.data
        db.session.commit()
        return redirect(url_for("cafes"))
    return render_template("add-cafe.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:cafe_id>")
@admin_only
def delete_cafe(cafe_id):
    cafe_to_delete = db.get_or_404(Cafe, cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('cafes'))


if __name__ == "__main__":
    app.run(debug=True, port=5002)