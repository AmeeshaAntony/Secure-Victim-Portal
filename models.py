from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from app import db

class PoliceOfficer(UserMixin, db.Model):  # UserMixin enables authentication
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Store hashed password
    station = db.Column(db.String(100), nullable=False)
    district = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)

    # Notification Preferences
    notify_email = db.Column(db.Boolean, default=True)
    notify_sms = db.Column(db.Boolean, default=False)
    notify_in_app = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<PoliceOfficer {self.username}>"
