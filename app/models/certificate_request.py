"""
Certificate Request model for tracking certificate generation metadata.

This model stores metadata about certificate generation requests,
including user agent, OS detection, and request details.
"""

from datetime import datetime, timezone
from app.extensions import db
from app.models.base import SecureModelMixin
from sqlalchemy import Text


class CertificateRequest(SecureModelMixin, db.Model):
    """
    Tracks metadata for certificate generation requests.

    This model captures information about who requested certificates,
    when they were requested, and details about the requesting environment
    (user agent, OS, IP address, etc.).
    """
    __tablename__ = 'certificate_requests'

    id = db.Column(db.Integer, primary_key=True)

    # Mass assignment protection - only allow these fields during creation/update
    _allowed_attributes = [
        'common_name', 'certificate_type', 'user_id', 'user_email',
        'client_ip', 'raw_user_agent', 'detected_os', 'os_version',
        'browser', 'browser_version', 'is_mobile', 'template_name',
        'template_set', 'signing_successful', 'signing_error_message',
        'request_source'
        # Note: certificate_serial intentionally excluded for security
    ]
    
    # Certificate identification
    common_name = db.Column(db.String(255), nullable=False, index=True)
    certificate_type = db.Column(db.String(20), nullable=False, default='user')  # 'user', 'server', 'device'
    
    # User/requester information
    user_id = db.Column(db.String(255), nullable=True, index=True)  # OIDC sub claim
    user_email = db.Column(db.String(255), nullable=True)
    
    # Request metadata
    request_timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    client_ip = db.Column(db.String(45), nullable=True)  # IPv4 (15 chars) or IPv6 (45 chars)
    
    # User Agent and OS detection
    raw_user_agent = db.Column(Text, nullable=True)  # Full user agent string
    detected_os = db.Column(db.String(50), nullable=True)  # 'Windows', 'macOS', 'Linux', 'iOS', 'Android'
    os_version = db.Column(db.String(50), nullable=True)  # '10', '14.6', 'Ubuntu', etc.
    browser = db.Column(db.String(50), nullable=True)  # 'Chrome', 'Firefox', 'Safari', etc.
    browser_version = db.Column(db.String(50), nullable=True)  # Browser version
    is_mobile = db.Column(db.Boolean, nullable=False, default=False)
    
    # Template and configuration used
    template_name = db.Column(db.String(100), nullable=True)
    template_set = db.Column(db.String(100), nullable=True)  # For PSK-based requests
    
    # Certificate signing details
    signing_successful = db.Column(db.Boolean, nullable=True)  # True/False/None (pending)
    signing_error_message = db.Column(Text, nullable=True)
    certificate_serial = db.Column(db.String(100), nullable=True)  # If available from signing service
    
    # Additional metadata
    request_source = db.Column(db.String(20), nullable=False, default='web')  # 'web', 'api'
    
    def __init__(self, **kwargs):
        """Initialize a new CertificateRequest record."""
        super(CertificateRequest, self).__init__(**kwargs)
    
    def __repr__(self):
        """String representation of the certificate request."""
        return f'<CertificateRequest {self.common_name} ({self.certificate_type}) at {self.request_timestamp}>'
    
    def to_dict(self):
        """Convert the certificate request to a dictionary."""
        return {
            'id': self.id,
            'common_name': self.common_name,
            'certificate_type': self.certificate_type,
            'user_id': self.user_id,
            'user_email': self.user_email,
            'request_timestamp': self.request_timestamp.isoformat() if self.request_timestamp else None,
            'client_ip': self.client_ip,
            'detected_os': self.detected_os,
            'os_version': self.os_version,
            'browser': self.browser,
            'browser_version': self.browser_version,
            'is_mobile': self.is_mobile,
            'template_name': self.template_name,
            'template_set': self.template_set,
            'signing_successful': self.signing_successful,
            'certificate_serial': self.certificate_serial,
            'request_source': self.request_source
        }
    
    def get_os_summary(self):
        """Get a human-readable OS summary."""
        if self.detected_os == 'Unknown':
            return 'Unknown'
        
        os_str = self.detected_os or 'Unknown'
        if self.os_version:
            os_str += f' {self.os_version}'
        return os_str
    
    def get_browser_summary(self):
        """Get a human-readable browser summary."""
        if self.browser == 'Unknown':
            return 'Unknown'
        
        browser_str = self.browser or 'Unknown'
        if self.browser_version:
            # Just show major version
            major_version = self.browser_version.split('.')[0] if '.' in self.browser_version else self.browser_version
            browser_str += f' {major_version}'
        
        if self.is_mobile:
            browser_str += ' (Mobile)'
            
        return browser_str
    
    @classmethod
    def create_from_request(cls, flask_request, common_name, certificate_type='user', 
                          user_info=None, template_name=None, template_set=None, 
                          request_source='web'):
        """
        Create a CertificateRequest record from a Flask request object.
        
        Args:
            flask_request: Flask request object
            common_name: Certificate common name
            certificate_type: Type of certificate ('user', 'server', 'device')
            user_info: User information dictionary (OIDC data)
            template_name: Template used for generation
            template_set: Template set (for PSK requests)
            request_source: Source of the request ('web', 'api')
            
        Returns:
            CertificateRequest instance
        """
        from app.utils.user_agent_detection import parse_user_agent
        
        # Parse user agent
        user_agent = flask_request.headers.get('User-Agent')
        ua_data = parse_user_agent(user_agent)
        
        # Extract client IP
        client_ip = flask_request.remote_addr
        if flask_request.headers.get('X-Forwarded-For'):
            forwarded_ips = flask_request.headers.get('X-Forwarded-For').split(',')
            if forwarded_ips:
                client_ip = forwarded_ips[0].strip()
        
        # Extract user information
        user_id = None
        user_email = None
        if user_info:
            user_id = user_info.get('sub')
            user_email = user_info.get('email', user_info.get('sub'))
        
        return cls(
            common_name=common_name,
            certificate_type=certificate_type,
            user_id=user_id,
            user_email=user_email,
            client_ip=client_ip,
            raw_user_agent=ua_data['raw_user_agent'],
            detected_os=ua_data['os'],
            os_version=ua_data['os_version'],
            browser=ua_data['browser'],
            browser_version=ua_data['browser_version'],
            is_mobile=ua_data['is_mobile'],
            template_name=template_name,
            template_set=template_set,
            request_source=request_source
        )