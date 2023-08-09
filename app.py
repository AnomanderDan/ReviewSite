from flask import Flask, render_template, redirect, url_for, request, flash
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
    """Gets user id"""
    return User.query.get(int(user_id))

# region models
class Game(db.Model):
    """Stores general game info"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    genre_id = db.Column(db.Integer, db.ForeignKey('genre.id'), nullable=False)
    image = db.Column(db.Text)
    synopsis = db.Column(db.Text)
    #display it nicely
    def __repr__(self) -> str:
        return f"Game: {self.name}"


class Genre(db.Model):
    """Stores genre info"""
    id = db.Column(db.Integer, primary_key=True)
    genre = db.Column(db.Text)
    games = db.relationship('Game', backref='genre', lazy=True)


class User(db.Model, UserMixin):
    """Stores user info"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    reviews = db.relationship('Reviews', backref='user', lazy=True)


class Reviews(db.Model):
    """stores reviews"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    review_text = db.Column(db.Text)
    current_game = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)


class GameReview(db.Model):
    """Stores game and review id"""
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    review_id = db.Column(db.Integer, db.ForeignKey('reviews.id'), nullable=False)\
#endregion

#region flask forms
class WriteReview(FlaskForm):
    """Review writing form"""
    write = StringField(validators=[InputRequired(), Length(min=1, max=1000)], render_kw={"placeholder" : "Write review here"})


class RegisterForm(FlaskForm):
    """Registration Flask Form"""
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")
    def validate_username(self, username):
        """Checks if username is already being used"""
        existing_user_name = User.query.filter_by(username=username.data).first()
        print(existing_user_name)
        if existing_user_name:
            flash("Username already exists")
            raise ValidationError("That username already exists. Please pick a new one.")     


class LoginForm(FlaskForm):
    """Login Form"""
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")
#endregion


#region routes
@app.route('/')
def home():
    """Goes to home page"""
    games = Game.query.all()
    genres = Genre.query.all()

    return render_template("mainpage.html", games=games, genres=genres)


@app.route('/game/<int:id>', methods=['GET', 'POST'])
def game(id):
    """This shows the game page """
    form = WriteReview()
    reviews = Reviews.query.filter(Reviews.current_game == id)
    gamename = Game.query.filter_by(id = id).first_or_404()
    #review = Game_Review.query.filter_by(id = id).first()
    if form.validate_on_submit():
        if current_user:
            new_review = Reviews(review_text=form.write.data, user_id=current_user.id, current_game=id)
            db.session.add(new_review)
            db.session.commit()
            return redirect('/game/' + str(id))
        else:
            return redirect('/Login')

    return render_template('game.html', game=gamename, form=form, reviews=reviews)


# 404 error page
@app.errorhandler(404)
def wrong(e):
    """404 Page"""
    return render_template("404.html"), 404


@app.route('/about')
def about():
    """The about page"""
    return render_template('about.html')


#login routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login Page"""
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Successfully Logged in")
                return redirect(url_for('home'))
        else:
            flash("That username or password is incorrect, please try again.")

    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    """Logout"""
    if current_user.is_authenticated:
        logout_user()
        flash("You have been successfully logged out")
        return redirect(url_for('login'))
    else:
        flash("You cannot logout when you are not signed in.")
        return redirect(url_for('register'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration Page"""
    form = RegisterForm()
    if form.validate_on_submit():
        flash("Successfully registered")
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/delete', methods=['GET', 'POST'])
def delete():
    """Delete Function"""
    item_id = int(request.form.get("review_id"))
    item = Reviews.query.filter_by(id = item_id).first_or_404()
    game_id = str(request.form.get('current_game'))
    db.session.delete(item)
    db.session.commit()
    flash("Review successfully deleted.")

    return redirect('/game/' + str(game_id))

#endregion


#app run
if __name__ == "__main__":
    app.run(debug=True)


#WRITE DOWN AN ABOUT PAGE
