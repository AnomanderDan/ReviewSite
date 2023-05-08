import sqlite3
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Integer, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user



#app
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///create.db"
app.config['SECRET_KEY'] =b'_5#y2L"F4Q8z\n\xec]/'
db = SQLAlchemy(app)


#classes

#Game/Genre classes
class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    review = db.Column(db.String)
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

# 404 error page
@app.errorhandler(404)
def wrong(e):
    return render_template("404.html"), 404

@app.route('/genre/<int:id>')
def sort(id):
    game = Game.query.filter_by(id = id).first_or_404()
    print(game)
    return render_template('sort.html', game=game)

@app.route('/login')
def login():

    return render_template('login.html')

@app.route('/register')
def login():

    return render_template('register.html')


if __name__ == "__main__":
    app.run(debug=True)