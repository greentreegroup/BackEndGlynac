from flask import Flask, jsonify
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_migrate import Migrate
from modules.common.config import Config
from modules.common.database import db
from modules.auth import init_app as init_auth
from modules.auth.seeds import run_seeds
from modules.common.docs import api
from datetime import datetime, UTC

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)
    CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins
    migrate = Migrate(app, db)
    
    # Initialize API documentation
    api.init_app(app)
    
    # Initialize auth module
    init_auth(app)
    
    # Health check endpoint
    @app.route('/ping', methods=['GET'])
    def ping():
        return jsonify({
            'status': 'success',
            'message': 'Server is running',
            'timestamp': datetime.now(UTC).isoformat()
        }), 200
    
    # Create database tables and seed initial data
    with app.app_context():
        db.create_all()
        run_seeds()  # Run seeds after tables are created
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True) 