from flask_sqlalchemy import SQLAlchemy
from app import app

db = SQLAlchemy(app)

class PoliceOfficer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"<PoliceOfficer {self.username}>"
