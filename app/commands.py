"""
Defines custom command line commands for the application.
"""

import click
import uuid
from datetime import datetime, timezone, timedelta
from flask import current_app
from flask.cli import with_appcontext
from app.extensions import db

@click.command('dev:create-psk')
@click.option('--description', required=True, help='Description for the PSK')
@click.option('--template-set', default='Default', help='Server template set to use (default: Default)')
@click.option('--expires-days', type=int, help='Number of days until expiration (optional)')
@click.option('--psk-type', type=click.Choice(['server', 'computer']), default='server', help='Type of PSK to create (default: server)')
@with_appcontext
def create_psk_command(description, template_set, expires_days, psk_type):
    """Creates a new PSK (DEVELOPMENT MODE ONLY)."""
    # Security check: Only allow in development mode
    environment = current_app.config.get('ENVIRONMENT', 'production')
    click.echo(f'DEBUG: Flask config ENVIRONMENT = {repr(environment)}', err=True)
    
    if environment != 'development':
        click.echo('ERROR: This command is only available in development mode!', err=True)
        click.echo('Set ENVIRONMENT=development to use this command.', err=True)
        return
    
    from app.models import PreSharedKey
    
    # Check if description already exists
    existing = PreSharedKey.query.filter_by(description=description).first()
    if existing:
        click.echo(f'ERROR: PSK for description "{description}" already exists!', err=True)
        return
    
    # Calculate expiration if specified
    expires_at = None
    if expires_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_days)
    
    # Generate plaintext PSK
    import uuid
    plaintext_psk = str(uuid.uuid4())
    
    # Create new PSK
    psk = PreSharedKey(description=description, template_set=template_set, expires_at=expires_at, key=plaintext_psk, psk_type=psk_type)
    db.session.add(psk)
    db.session.commit()

    click.echo('=== DEVELOPMENT MODE PSK CREATED ===')
    click.echo(f'Description: {description}')
    click.echo(f'Template Set: {template_set}')
    click.echo(f'PSK Type: {psk_type}')
    click.echo(f'PSK: {plaintext_psk}')
    if expires_at:
        click.echo(f'Expires: {expires_at.isoformat()}')
    else:
        click.echo('Expires: Never')
    click.echo('=====================================')
    
@click.command('dev:create-dev-auth')
@click.option('--username', default='dev-user', help='Username for development auth')
@click.option('--email', default='dev@example.com', help='Email for development auth')
@click.option('--admin', is_flag=True, help='Grant admin privileges')
@with_appcontext
def create_dev_auth_command(username, email, admin):
    """Creates development authentication token (DEVELOPMENT MODE ONLY)."""
    # Security check: Only allow in development mode
    environment = current_app.config.get('ENVIRONMENT', 'production')
    click.echo(f'DEBUG: Flask config ENVIRONMENT = {repr(environment)}', err=True)
    
    if environment != 'development':
        click.echo('ERROR: This command is only available in development mode!', err=True)
        click.echo('Set ENVIRONMENT=development to use this command.', err=True)
        return
    
    # Generate a development auth token
    auth_token = f'dev-auth-{uuid.uuid4()}'
    
    groups = []
    if admin:
        admin_group = current_app.config.get('OIDC_ADMIN_GROUP', 'admins')
        groups.append(admin_group)
    
    click.echo('=== DEVELOPMENT MODE AUTH TOKEN ===')
    click.echo(f'Username: {username}')
    click.echo(f'Email: {email}')
    click.echo(f'Groups: {groups}')
    click.echo(f'Auth Token: {auth_token}')
    click.echo('====================================')
    click.echo('Use this token by setting the X-Dev-Auth header:')
    click.echo(f'curl -H "X-Dev-Auth: {auth_token}" http://localhost:8000/')
    click.echo('====================================')

def init_commands(app):
    app.cli.add_command(create_psk_command)
    app.cli.add_command(create_dev_auth_command)