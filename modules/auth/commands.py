"""
CLI commands for the auth module.
"""

import click
from flask.cli import with_appcontext
from .seeds import run_seeds

@click.command('seed-db')
@with_appcontext
def seed_db_command():
    """Seed the database with initial data."""
    run_seeds() 