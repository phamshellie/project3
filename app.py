from flask import Flask
from auth import auth_blueprint
from database import init_db

app = Flask(__name__)
app.register_blueprint(auth_blueprint)
init_db()  #initialize database tables

if __name__ == '__main__':
    app.run(debug=True)
