from datetime import datetime

from flask_security import UserMixin, RoleMixin
from flask import render_template

from mhn import db
from mhn.api import APIModel


roles_users = db.Table(
        'roles_users', db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, APIModel, UserMixin):
    __table_args__ = (
        db.Index('idx_user_email', 'email'),
        db.Index('idx_user_active', 'active'),
        db.Index('idx_user_confirmed_at', 'confirmed_at'),
    )
    
    all_fields = {
        'email': {'required': True, 'editable': False},
        'password': {'required': True, 'editable': True},
        'active': {'required': False, 'editable': True}
    }

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean(), default=True, nullable=False)
    confirmed_at = db.Column(db.DateTime(), nullable=True)
    fs_uniquifier = db.Column(db.String(255), unique=True, nullable=False)
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def to_dict(self):
        return dict(
                email=self.email, roles=[r.name for r in self.roles],
                active=self.active)


class PasswdReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hashstr = db.Column(db.String(40))
    created = db.Column(db.DateTime(), default=datetime.utcnow)
    active = db.Column(db.Boolean())
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
    user = db.relationship(User, uselist=False)

    @property
    def email_body(self):
        from mhn import mhn
        return render_template(
                'auth/reset-email.html', hashstr=self.hashstr,
                 server_url=mhn.config['SERVER_BASE_URL'],
                 email=self.user.email)


class ApiKey(db.Model):
    all_fields = {
        'api_key': {'required': True, 'editable': False},
        'user_id': {'required': True, 'editable': False}
    }

    id = db.Column(db.Integer, primary_key=True)
    api_key = db.Column(db.String(32), unique=True)
    user_id = db.Column('user_id', db.Integer, db.ForeignKey("user.id"), nullable=False)
