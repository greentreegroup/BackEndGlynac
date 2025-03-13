# Glynac Backend API

A Flask-based REST API with JWT authentication, user management, and session handling.

## Features

- JWT-based authentication
- User registration and login
- Session management
- Role-based access control (Admin/Client)
- CORS enabled
- PostgreSQL database
- API documentation with Swagger UI

## Prerequisites

- Python 3.8 or higher
- PostgreSQL database
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd BackEndGlynac
```

2. Create and activate a virtual environment:
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory with the following variables:
```env
# Flask Application Settings
SECRET_KEY=your-secret-key-here
JWT_SECRET_KEY=your-jwt-secret-key-here

# Database Configuration
DATABASE_URL=postgresql://username:password@localhost:5432/database_name

# Security Settings
MAX_LOGIN_ATTEMPTS=5
LOGIN_TIMEOUT_MINUTES=15

# JWT Token Settings
JWT_ACCESS_TOKEN_EXPIRES=3600  # 1 hour in seconds
JWT_REFRESH_TOKEN_EXPIRES=2592000  # 30 days in seconds
```

## Database Setup

1. Create a PostgreSQL database:
```sql
CREATE DATABASE database_name;
```

2. Run database migrations:
```bash
flask db upgrade
```

## Running the Application

1. Start the Flask development server:
```bash
python app.py
```

The server will start at `http://localhost:5000`

## API Documentation

Access the Swagger UI documentation at:
```
http://localhost:5000/
```

## API Endpoints

### Authentication

#### Register
```http
POST /auth/register
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecureP@ss123",
    "full_name": "John Doe",
    "phone": "+1234567890",
    "role": "client"
}
```

#### Login
```http
POST /auth/login
Content-Type: application/json

{
    "email": "user@example.com",
    "password": "SecureP@ss123"
}
```

#### Refresh Token
```http
POST /auth/refresh-token
Content-Type: application/json

{
    "refresh_token": "your-refresh-token"
}
```

#### Logout
```http
POST /auth/logout
Content-Type: application/json

{
    "refresh_token": "your-refresh-token"
}
```

### Session Management

#### Get Active Sessions
```http
GET /auth/sessions
Authorization: Bearer your-access-token
```

#### Delete Specific Session
```http
DELETE /auth/sessions/{session_id}
Authorization: Bearer your-access-token
```

#### Revoke All Sessions
```http
POST /auth/sessions/revoke-all
Authorization: Bearer your-access-token
```

## Default Users

The application comes with pre-seeded users:

### Admin User
- Email: admin@glynac.com
- Password: Admin@123
- Role: admin

### Client Users
- Email: client1@glynac.com
- Password: Client@123
- Role: client

- Email: client2@glynac.com
- Password: Client@123
- Role: client

- Email: client3@glynac.com
- Password: Client@123
- Role: client

## Security Features

- Password hashing using bcrypt
- JWT token-based authentication
- Session management
- Rate limiting for login attempts
- CORS protection
- Input validation
- SQL injection prevention

## Error Handling

The API returns standardized error responses in the following format:
```json
{
    "error": "Error message",
    "details": {
        "field": "Field-specific error message"
    },
    "missing_fields": ["field1", "field2"]
}
```

## Development

### Running Tests
```bash
# Add test command when implemented
```

### Code Style
The project follows PEP 8 guidelines. Use a code formatter like `black` to maintain consistent code style.

## License

[Add your license information here]
