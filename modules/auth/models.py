from datetime import datetime
import uuid
from ..common.database import db
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from enum import Enum

class UserRole(str, Enum):
    ADMIN = 'admin'
    CLIENT = 'client'

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = db.Column(db.String(255), unique=True, nullable=False)
    encrypted_password = db.Column(db.String(255))
    full_name = db.Column(db.String(255))
    phone = db.Column(db.Text)
    role = db.Column(db.Enum(UserRole), default=UserRole.CLIENT)
    email_confirmed_at = db.Column(db.DateTime)
    phone_confirmed_at = db.Column(db.DateTime)
    last_sign_in_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_super_admin = db.Column(db.Boolean, default=False)
    is_sso_user = db.Column(db.Boolean, default=False)
    is_anonymous = db.Column(db.Boolean, default=False)
    raw_app_meta_data = db.Column(JSONB)
    raw_user_meta_data = db.Column(JSONB)
    account_status = db.Column(db.Text, default='Active')
    profile_image_url = db.Column(db.Text)
    preferences = db.Column(JSONB)
    is_deleted = db.Column(db.Boolean, default=False)

    # Relationships
    auths = db.relationship('Auth', backref='user', lazy=True)
    sessions = db.relationship('Session', backref='user', lazy=True)

class Auth(db.Model):
    __tablename__ = 'auths'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    provider = db.Column(db.String(100), nullable=False)
    provider_id = db.Column(db.String(255))
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    expires_at = db.Column(db.DateTime)
    invalidated = db.Column(db.Boolean, default=False)  # New field
    invalidated_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'), nullable=False)
    access_token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text, nullable=False)
    ip_address = db.Column(INET, nullable=False)  # Using PostgreSQL INET type for IP addresses
    user_agent = db.Column(db.Text)
    location = db.Column(db.Text)
    expires_at = db.Column(db.DateTime, nullable=False)
    invalidated = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    invalidated_at = db.Column(db.DateTime)

class AuthAttempts(db.Model):
    __tablename__ = 'auth_attempts'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'))
    ip_address = db.Column(INET, nullable=False)  # Using PostgreSQL INET type for IP addresses
    attempt_count = db.Column(db.Integer, default=0)
    last_attempt_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'ip_address', name='uix_user_ip'),
    )

class FailedLogin(db.Model):
    __tablename__ = 'failed_logins'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = db.Column(UUID(as_uuid=True), db.ForeignKey('users.id'))
    ip_address = db.Column(INET, nullable=False)  # Using PostgreSQL INET type for IP addresses
    user_agent = db.Column(db.Text)
    location = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

