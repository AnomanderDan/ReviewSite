import sqlite3
from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt


#app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///create.db"
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] ='_5#y2L"F4Q8z\n\xec]/'
db = SQLAlchemy(app)


#login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="Login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#classes

#Game/Genre classes
class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    genre_id = db.Column(db.Integer, db.ForeignKey('genre.id'), nullable=False)
    image = db.Column(db.String)
    synopsis = db.Column(db.String)
    #display it nicely
    def __repr__(self) -> str:
        return f"Game: {self.game}"


class Genre(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    genre = db.Column(db.String)
    games = db.relationship('Game', backref='genre', lazy=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(
            username=username.data).first()
        
        if existing_user_name:
            raise ValidationError(
                "That username already exists. Please pick a new one.")



class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

#routes
@app.route('/')
def home():
    games = Game.query.all()
    genres = Genre.query.all()

    return render_template("mainpage.html", games=games, genres=genres)


@app.route('/game/<int:id>')
def game(id):
    game = Game.query.filter_by(id = id).first_or_404()

    return render_template('game.html', game=game)


@app.route('/genre/<int:id>')
def sort(id):
    game = Game.query.filter_by(id = id).first_or_404()
    print(game)
    return render_template('sort.html', game=game)


# 404 error page
@app.errorhandler(404)
def wrong(e):
    return render_template("404.html"), 404


#login routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# @app.route('/comment', methods=['GET', 'POST'])
# @login_required
# def comment():


#app run
if __name__ == "__main__":
    app.run(debug=True)