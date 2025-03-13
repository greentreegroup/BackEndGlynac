"""
Database seed module for authentication.
This module provides functions to seed the database with initial data.
"""

import bcrypt
from datetime import datetime
from .models import User, UserRole
from ..common.database import db

def seed_users():
    """Seed initial users including admin and clients"""
    
    # Check if users table is empty
    if User.query.first() is not None:
        print("Users table is not empty. Skipping seed.")
        return
    
    print("Users table is empty. Starting seed...")
    
    # Create admin user
    admin_password = bcrypt.hashpw('Admin@123'.encode('utf-8'), bcrypt.gensalt())
    admin = User(
        email='admin@glynac.com',
        encrypted_password=admin_password.decode('utf-8'),
        full_name='System Administrator',
        role=UserRole.ADMIN,
        email_confirmed_at=datetime.utcnow(),
        account_status='Active'
    )
    
    # Create client users
    client_password = bcrypt.hashpw('Client@123'.encode('utf-8'), bcrypt.gensalt())
    clients = [
        User(
            email='client1@glynac.com',
            encrypted_password=client_password.decode('utf-8'),
            full_name='John Client',
            role=UserRole.CLIENT,
            email_confirmed_at=datetime.utcnow(),
            account_status='Active'
        ),
        User(
            email='client2@glynac.com',
            encrypted_password=client_password.decode('utf-8'),
            full_name='Jane Client',
            role=UserRole.CLIENT,
            email_confirmed_at=datetime.utcnow(),
            account_status='Active'
        ),
        User(
            email='client3@glynac.com',
            encrypted_password=client_password.decode('utf-8'),
            full_name='Bob Client',
            role=UserRole.CLIENT,
            email_confirmed_at=datetime.utcnow(),
            account_status='Active'
        )
    ]
    
    try:
        # Add all users to session
        db.session.add(admin)
        for client in clients:
            db.session.add(client)
        
        # Commit the transaction
        db.session.commit()
        print("Successfully seeded users")
        
    except Exception as e:
        db.session.rollback()
        print(f"Error seeding users: {str(e)}")
        raise

def run_seeds():
    """Run all seed functions"""
    print("Starting database seeding...")
    seed_users()
    print("Database seeding completed") 