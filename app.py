from flask import Flask, after_this_request, flash, render_template, redirect, request, session, url_for
from flask_bcrypt import Bcrypt
import secrets
import sqlite3

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(22)

def get_db():
    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    return conn

def create_bcrypt():
    return Bcrypt(app)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    bcrypt = create_bcrypt()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        db = get_db()
        cur = db.cursor()
        # Get users When username, and password match
        cur.execute("SELECT * FROM users WHERE username == ?", (username,))
        user_info = cur.fetchone()
        db.commit()

        if not user_info:
            flash("User not found")
            return redirect("/login")

        # If password does not match
        if not bcrypt.check_password_hash(user_info["password"], password):
            flash("Invalid password")
            return redirect("/login")

        session["user_id"] = user_info["id"]

        return redirect("/login")

    else:
        return render_template("login.html")
    


@app.route("/signup", methods=["GET", "POST"])
def signup():
    """ Get username and password then insert into database """

    # TODO Add username, and password limitations

    bcrypt = create_bcrypt()

    if request.method == "POST":
        # TODO Make input more secure from user
        
        name = request.form.get("username")
        # Hash password  
        password = bcrypt.generate_password_hash(request.form.get("password")).decode('utf-8')
        

        try:

            db = get_db()
            cur = db.cursor()

            cur.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                        (name, password))
            db.commit()

        except sqlite3.IntegrityError:
            flash("User Already Exists")
            return redirect("/signup")


        return redirect("/login")

    return render_template("signup.html")

if __name__ == "__main__":
    app.run(debug=True)