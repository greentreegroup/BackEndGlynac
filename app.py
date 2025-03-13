from flask import Flask, jsonify, url_for
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_migrate import Migrate
from modules.common.config import Config
from modules.common.database import db
from modules.auth import init_app as init_auth
from modules.auth.seeds import run_seeds
from modules.common.docs import api
from datetime import datetime, UTC
import click

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins
    migrate = Migrate(app, db)
    
    # Initialize auth module first (this registers the routes with the namespaces)
    init_auth(app)
    
    # Initialize API documentation after routes are registered
    api.init_app(app)
    
    # Health check endpoint
    @app.route('/ping', methods=['GET'])
    def ping():
        return jsonify({
            'status': 'success',
            'message': 'Server is running',
            'timestamp': datetime.now(UTC).isoformat()
        }), 200

    # Debug endpoint to list all routes (only in development)
    @app.route('/debug/routes')
    def list_routes():
        if app.config.get('ENV') != 'production':
            routes = []
            for rule in app.url_map.iter_rules():
                methods = ','.join(sorted(rule.methods))
                routes.append({
                    'endpoint': rule.endpoint,
                    'methods': methods,
                    'path': str(rule)
                })
            return jsonify(sorted(routes, key=lambda x: x['path']))
        return jsonify({'error': 'Not available in production'}), 403

    # CLI command to list routes
    @app.cli.command('list-routes')
    def list_routes_command():
        """List all registered routes"""
        rows = []
        for rule in app.url_map.iter_rules():
            methods = ','.join(sorted(rule.methods))
            rows.append({
                'endpoint': rule.endpoint,
                'methods': methods,
                'path': str(rule)
            })
        
        # Sort routes by path
        rows = sorted(rows, key=lambda x: x['path'])
        
        # Print in a formatted way
        click.echo("\nRegistered Routes:")
        click.echo("-" * 100)
        click.echo(f"{'Path':<50} {'Methods':<20} {'Endpoint':<30}")
        click.echo("-" * 100)
        for row in rows:
            click.echo(f"{row['path']:<50} {row['methods']:<20} {row['endpoint']:<30}")
        click.echo("-" * 100)
    
    # Create database tables and seed initial data
    with app.app_context():
        db.create_all()
        run_seeds()  # Run seeds after tables are created
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True) 