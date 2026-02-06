# Frontend Service

This file provides LLMs with guidance for working with the Frontend Service component of OpenVPN Manager.

## Service Overview

The Frontend Service is the main web UI and API gateway for OpenVPN Manager, running on ports 8450/8540/8600. It handles user authentication, certificate management, and orchestrates communication between the signing and certificate transparency services.

## Architecture

### Flask Application Structure
- `app/` - Main application directory
  - `routes/` - Route handlers for different endpoints
    - `api/v1.py` - REST API endpoints
    - `auth.py` - OIDC authentication handling
    - `profile.py` - User profile management
    - `admin.py` - Administrative interfaces
    - `certificates.py` - Certificate management
    - `download.py` - File download handling
    - `crl.py` - Certificate revocation lists
  - `models/` - SQLAlchemy database models
    - `presharedkey.py` - PSK management
    - `downloadtoken.py` - Download token management
    - `types/` - Custom SQLAlchemy types (encrypted fields)
  - `utils/` - Utility modules
    - `decorators.py` - Custom decorators for authentication/authorization
  - `templates/` - Jinja2 HTML templates
  - `static/` - Static assets (CSS, JS, images)

### Database Models
- PostgreSQL database with Flask-SQLAlchemy ORM
- Flask-Migrate for schema versioning
- Encrypted field support for sensitive data
- Models support both user and admin functionality

### Deployment Modes
The service supports three deployment configurations:
1. **Combined Mode** (default): All functionality in single service
2. **User Service**: Set `ADMIN_URL_BASE`, serves only user routes  
3. **Admin Service**: Set `USER_URL_BASE`, serves only admin routes

## Key Dependencies

- **Flask**: Web framework
- **Authlib**: OIDC authentication
- **Flask-SQLAlchemy**: Database ORM
- **psycopg2-binary**: PostgreSQL adapter
- **cryptography**: Certificate operations
- **Flask-Limiter + redis**: Rate limiting
- **Flask-Migrate**: Database migrations
- **Flask-Talisman**: Security headers
- **Jinja2**: Template rendering
- **user-agents**: Client detection
- **flask-swagger-ui**: API documentation

## Development Workflow

### Local Development
```bash
cd services/frontend

# Install dependencies
pip install -r requirements.txt

# Run database migrations
./run_migrate.sh

# Run with Flask development server
flask run

# Run with Gunicorn (production-like)
gunicorn wsgi:app
```

### Testing
```bash
# Unit tests
python -m pytest tests/unit/ -v

# Integration tests  
python -m pytest tests/integration/ -v

# Functional tests
python -m pytest tests/functional/ -v

# All tests with coverage
python -m pytest tests/ --cov=app --cov-report=html
```

### Database Operations
```bash
# Create new migration
flask db migrate -m "Description of changes"

# Apply migrations
flask db upgrade

# Downgrade migrations  
flask db downgrade
```

## API Endpoints

### REST API (v1)
- `POST /api/v1/profile` - Generate user certificate profiles
- `POST /api/v1/computer/bundle` - Generate computer certificate profiles (PSK auth, single OVPN file)
- `GET /api/v1/server-bundle/{psk}` - Download server configuration bundles
- `GET /api/v1/certificates` - Query certificate transparency logs
- `GET /api/v1/health` - Health check endpoint

### Web Interface Routes
- `/` - Landing page
- `/profile` - User profile management
- `/admin` - Administrative interface
- `/certificates` - Certificate browser
- `/download/{token}` - Secure file downloads

## Configuration

### Environment Variables
- `FLASK_ENV` - Development/production mode
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection for rate limiting
- `SECRET_KEY` - Flask session encryption key
- `OIDC_*` - OIDC provider configuration
- `SIGNING_SERVICE_URL` - Signing service endpoint
- `CERTTRANSPARENCY_SERVICE_URL` - CT service endpoint
- `*_API_SECRET_FILE` - API secret file paths for service communication

### Service Integration
- Authenticates with signing service using shared secrets
- Logs all certificate operations to CT service
- Handles file uploads and secure downloads
- Manages user sessions and OIDC tokens

## Security Features

### Authentication & Authorization
- OIDC integration with group-based RBAC
- PKCE (RFC 7636) with S256 code challenge for authorization code flow security
- Session management with Flask-Session
- API authentication for service-to-service calls
- Rate limiting on sensitive endpoints

### Data Protection
- Encrypted database fields for sensitive data
- Secure file handling for certificates and keys
- CSRF protection with Flask-WTF
- Security headers via Flask-Talisman

## Testing Standards

- **100% test coverage required**
- Unit tests for individual functions and classes
- Integration tests for service interactions
- Functional tests for complete workflows
- Mock external service dependencies in tests

## Common Operations

### Adding New Routes
1. Create route handler in appropriate `routes/` module
2. Add authentication/authorization decorators
3. Implement request validation
4. Add comprehensive tests
5. Update API documentation if REST endpoint

### Database Changes
1. Modify models in `models/` directory
2. Create migration with `flask db migrate`
3. Test migration up and down
4. Update model tests
5. Consider data migration if needed

### Service Communication
- Use shared API secrets for authentication
- Implement proper error handling and retries
- Log all inter-service calls for debugging
- Handle service unavailability gracefully

## Debugging & Monitoring

### Logging
- Structured JSON logging in production
- Request/response logging for API calls
- Error tracking with stack traces
- Performance metrics for slow queries

### Health Checks
- Database connectivity validation
- External service availability checks
- Resource usage monitoring
- Certificate expiration alerts

## File Structure Notes

- `migrations/` - Flask-Migrate database schemas
- `tests/` - Comprehensive test suite
- `wsgi.py` - WSGI application entry point
- `run_migrate.sh` - Database migration helper
- `Dockerfile` - Container build configuration
- `.coveragerc` - Coverage configuration
- `pytest.ini` - Test runner configuration