import sqlite3
from flask import Flask, render_template, redirect, url_for, config, request, flash, abort
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
class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Text)
    genre_id = db.Column(db.Integer, db.ForeignKey('genre.id'), nullable=False)
    image = db.Column(db.Text)
    synopsis = db.Column(db.Text)
    #display it nicely
    def __repr__(self) -> str:
        return f"Game: {self.name}"


class Genre(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    genre = db.Column(db.Text)
    games = db.relationship('Game', backref='genre', lazy=True)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    reviews = db.relationship('Reviews', backref='user', lazy=True)


class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    review_text = db.Column(db.Text)
    current_game = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    

class Game_Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)
    review_id = db.Column(db.Integer, db.ForeignKey('reviews.id'), nullable=False)


class Write_Review(FlaskForm):
    write = StringField(validators=[InputRequired(), Length(min=1, max=1000)], render_kw={"placeholder" : "Write review here"})


class Update_Review(FlaskForm):
    update = StringField(validators=[InputRequired(), Length(min=1, max=1000)], render_kw={"placeholder" : "Update Review"})



class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_name = User.query.filter_by(username=username.data).first()
        print(existing_user_name)

        if existing_user_name:
            flash("Username already exists")
            raise ValidationError("That username already exists. Please pick a new one.")
            


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


@app.route('/game/<int:id>', methods=['GET', 'POST'])
def game(id):
    form = Write_Review()
    reviews = Reviews.query.filter(Reviews.current_game == id)
    game = Game.query.filter_by(id = id).first_or_404()
    #review = Game_Review.query.filter_by(id = id).first()
    if form.validate_on_submit():
        if current_user:
            new_review = Reviews(review_text=form.write.data, user_id=current_user.id, current_game=id)
            db.session.add(new_review)
            db.session.commit()
            return redirect('/game/' + str(id))
        else:
            return redirect('/Login')

    return render_template('game.html', game=game, form=form, reviews=reviews)


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
                flash("Successfully Logged in")
                return redirect(url_for('home'))
            
        else:
            flash("That username or password do not exist, please try again")

    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    form = LoginForm()
    user = User.query.filter_by(username=form.username.data).first()
    if user is user:
        logout_user()
        flash("You have been successfully logged out")
        return redirect(url_for('login'), user=user)
    
    else:
        return redirect(url_for('wrong'))
    #logout_user()
    #flash("You have been successfully logged out")
    #return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
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
    item_id = int(request.form.get("review_id"))
    item = Reviews.query.filter_by(id = item_id).first_or_404()
    game_id = str(request.form.get('current_game'))
    db.session.delete(item)
    db.session.commit()
    flash("Review successfully deleted")

    return redirect('/game/' + str(game_id))


#app run
if __name__ == "__main__":
    app.run(debug=True)