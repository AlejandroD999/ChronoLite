from flask import Flask, after_this_request, flash, render_template, redirect, request, session, url_for
from flask_bcrypt import Bcrypt
from datetime import timedelta
import secrets
import sqlite3

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(22)
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=3)
def get_db():
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    return conn

def create_bcrypt():
    return Bcrypt(app)

def password_passes_requirements(password):

    if len(password) < 6:
        return False
    


@app.route("/")
def home():
    if 'logged_in' in session and session["logged_in"]:
        return render_template("home/home.html")
    else:
        return redirect(url_for('login'))



@app.route("/login", methods=["GET", "POST"])
def login():

    bcrypt = create_bcrypt()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        # TODO Close database cursor and do try & except
        
        db = get_db()
        cur = db.cursor()
        # Get users When username, and password match
        cur.execute("SELECT * FROM users WHERE username == ?", (username,))
        user_info = cur.fetchone()
        db.commit()


        # If password does not match or user doesn't exist
        if not user_info or not bcrypt.check_password_hash(user_info["password"], password):
            flash("Invalid username or password")
            return redirect("/login")


        session["username"] = user_info["username"]
        session["logged_in"] = True
        session.permanent = True

        return redirect(url_for("home"))

    else:
        return render_template("access/login.html")
    


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """ Get username and password then insert into database """

    # TODO Add username, and password limitations

    bcrypt = create_bcrypt()

    if request.method == "POST":
        # TODO Make input more secure from user
        
        name = request.form.get("username")
        # Hash password  
        password = request.form.get("password")

        if not password_passes_requirements(password):
            flash("Password must include 6 or more characters")
            return redirect(url_for("signup"))
        
        if not name or not password:
            flash("Input must be valid")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        


        try:

            db = get_db()
            cur = db.cursor()

            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                        (name, hashed_password))
            
            db.commit()
            db.close()

        except sqlite3.IntegrityError:
            flash("User Already Exists")
            return redirect("/signup")


        return redirect("/login")

    return render_template("access/signup.html")


if __name__ == "__main__":
    app.run(debug=True)