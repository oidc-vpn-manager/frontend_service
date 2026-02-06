"""
Security Event Logging - Structured JSON logging for audit trails and SIEM compatibility

This module provides structured logging for security events that can be easily consumed
by SIEM systems and audit tools. All security events are logged in JSON format with
standardized fields for consistent analysis.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from flask import request, session, current_app, g
from functools import wraps
import uuid


class SecurityEventLogger:
    """
    Centralized security event logger that outputs structured JSON logs
    suitable for SIEM ingestion and audit trail analysis.
    """

    # Security event categories
    AUTH_EVENT = "authentication"
    AUTHZ_EVENT = "authorization"
    CERT_EVENT = "certificate"
    API_EVENT = "api_security"
    DATA_EVENT = "data_access"
    ADMIN_EVENT = "administration"
    SECURITY_EVENT = "security_violation"
    SYSTEM_EVENT = "system"

    # Event severity levels
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __init__(self):
        self.logger = logging.getLogger('security_events')

    def _get_request_context(self) -> Dict[str, Any]:
        """Extract request context information for logging."""
        context = {}

        if request:
            context.update({
                'request_id': getattr(g, 'request_id', str(uuid.uuid4())),
                'remote_addr': request.remote_addr,
                'method': request.method,
                'path': request.path,
                'url': request.url,
                'user_agent': request.headers.get('User-Agent', ''),
                'referrer': request.headers.get('Referer', ''),
                'content_type': request.content_type,
                'query_string': request.query_string.decode('utf-8') if request.query_string else '',
            })

            # Add forwarded IP if present
            forwarded_for = request.headers.get('X-Forwarded-For')
            if forwarded_for:
                context['forwarded_for'] = forwarded_for.split(',')[0].strip()

            # Add session info if available
            if session and 'user' in session:
                user_info = session['user']
                context.update({
                    'user_id': user_info.get('sub', ''),
                    'user_email': user_info.get('email', ''),
                    'user_name': user_info.get('name', ''),
                    'user_groups': user_info.get('groups', []),
                })

        return context

    def _log_security_event(self,
                           event_type: str,
                           action: str,
                           severity: str = MEDIUM,
                           success: bool = True,
                           message: str = "",
                           additional_data: Optional[Dict[str, Any]] = None) -> None:
        """
        Log a structured security event.

        Args:
            event_type: Category of security event (AUTH_EVENT, CERT_EVENT, etc.)
            action: Specific action being performed (login, certificate_issue, etc.)
            severity: Event severity level (LOW, MEDIUM, HIGH, CRITICAL)
            success: Whether the action was successful
            message: Human-readable description of the event
            additional_data: Additional context-specific data
        """

        # Base event structure
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'action': action,
            'severity': severity,
            'success': success,
            'message': message,
            'service': 'oidc-vpn-manager-frontend',
            'version': '1.0',
        }

        # Add request context
        event.update(self._get_request_context())

        # Add additional data if provided
        if additional_data:
            # Sanitize additional data to remove sensitive information
            sanitized_data = self._sanitize_data(additional_data)
            event['additional_data'] = sanitized_data

        # Log as JSON
        self.logger.info(json.dumps(event, default=str))

    def _sanitize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove or mask sensitive data before logging."""
        sensitive_keys = {
            'password', 'passwd', 'secret', 'private_key',
            'api_key', 'session_id', 'csrf_token', 'authorization'
        }

        sanitized = {}
        for key, value in data.items():
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_data(value)
            elif isinstance(value, str) and len(value) > 500:
                # Truncate very long strings
                sanitized[key] = value[:500] + '...[TRUNCATED]'
            else:
                sanitized[key] = value

        return sanitized

    # Authentication Events
    def log_authentication_attempt(self, user_id: str, success: bool,
                                 method: str = "oidc", failure_reason: str = "") -> None:
        """Log user authentication attempts."""
        message = f"User authentication {'succeeded' if success else 'failed'} via {method}"
        if not success and failure_reason:
            message += f": {failure_reason}"

        self._log_security_event(
            event_type=self.AUTH_EVENT,
            action="authentication_attempt",
            severity=self.MEDIUM if success else self.HIGH,
            success=success,
            message=message,
            additional_data={
                'target_user_id': user_id,
                'auth_method': method,
                'failure_reason': failure_reason if not success else None
            }
        )

    def log_logout(self, user_id: str) -> None:
        """Log user logout events."""
        self._log_security_event(
            event_type=self.AUTH_EVENT,
            action="logout",
            severity=self.LOW,
            success=True,
            message=f"User {user_id} logged out",
            additional_data={'target_user_id': user_id}
        )

    def log_session_fixation_attempt(self, session_id: str, user_id: str = "") -> None:
        """Log potential session fixation attempts."""
        self._log_security_event(
            event_type=self.SECURITY_EVENT,
            action="session_fixation_attempt",
            severity=self.HIGH,
            success=False,
            message="Potential session fixation attack detected",
            additional_data={
                'session_id': session_id[:8] + '...',  # Partial session ID
                'target_user_id': user_id
            }
        )

    # Authorization Events
    def log_access_denied(self, resource: str, required_permission: str,
                         user_id: str = "", reason: str = "") -> None:
        """Log access denied events."""
        self._log_security_event(
            event_type=self.AUTHZ_EVENT,
            action="access_denied",
            severity=self.MEDIUM,
            success=False,
            message=f"Access denied to {resource}",
            additional_data={
                'resource': resource,
                'required_permission': required_permission,
                'target_user_id': user_id,
                'denial_reason': reason
            }
        )

    def log_privilege_escalation_attempt(self, user_id: str, attempted_action: str,
                                       current_groups: list, attempted_groups: list = None) -> None:
        """Log potential privilege escalation attempts."""
        self._log_security_event(
            event_type=self.SECURITY_EVENT,
            action="privilege_escalation_attempt",
            severity=self.CRITICAL,
            success=False,
            message=f"Privilege escalation attempt by {user_id}",
            additional_data={
                'target_user_id': user_id,
                'attempted_action': attempted_action,
                'current_groups': current_groups,
                'attempted_groups': attempted_groups
            }
        )

    # Certificate Events
    def log_certificate_issued(self, common_name: str, certificate_type: str,
                              fingerprint: str, user_id: str = "") -> None:
        """Log certificate issuance events."""
        self._log_security_event(
            event_type=self.CERT_EVENT,
            action="certificate_issued",
            severity=self.MEDIUM,
            success=True,
            message=f"Certificate issued for {common_name}",
            additional_data={
                'common_name': common_name,
                'certificate_type': certificate_type,
                'fingerprint': fingerprint,
                'issuing_user_id': user_id
            }
        )

    def log_certificate_revoked(self, fingerprint: str, revocation_reason: str,
                               user_id: str = "", bulk_operation: bool = False) -> None:
        """Log certificate revocation events."""
        action = "bulk_certificate_revocation" if bulk_operation else "certificate_revoked"
        self._log_security_event(
            event_type=self.CERT_EVENT,
            action=action,
            severity=self.HIGH,
            success=True,
            message=f"Certificate revoked: {fingerprint[:16]}...",
            additional_data={
                'fingerprint': fingerprint,
                'revocation_reason': revocation_reason,
                'revoking_user_id': user_id,
                'bulk_operation': bulk_operation
            }
        )

    def log_certificate_download(self, certificate_type: str, user_id: str = "",
                                template_set: str = "") -> None:
        """Log certificate/profile download events."""
        self._log_security_event(
            event_type=self.CERT_EVENT,
            action="certificate_download",
            severity=self.LOW,
            success=True,
            message=f"Certificate profile downloaded: {certificate_type}",
            additional_data={
                'certificate_type': certificate_type,
                'requesting_user_id': user_id,
                'template_set': template_set
            }
        )

    # API Security Events
    def log_api_authentication_failure(self, endpoint: str, auth_method: str,
                                     failure_reason: str) -> None:
        """Log API authentication failures."""
        self._log_security_event(
            event_type=self.API_EVENT,
            action="api_authentication_failure",
            severity=self.HIGH,
            success=False,
            message=f"API authentication failed for {endpoint}",
            additional_data={
                'endpoint': endpoint,
                'auth_method': auth_method,
                'failure_reason': failure_reason
            }
        )

    def log_api_rate_limit_exceeded(self, endpoint: str, limit: int, user_id: str = "") -> None:
        """Log API rate limit violations."""
        self._log_security_event(
            event_type=self.API_EVENT,
            action="rate_limit_exceeded",
            severity=self.MEDIUM,
            success=False,
            message=f"Rate limit exceeded for {endpoint}",
            additional_data={
                'endpoint': endpoint,
                'rate_limit': limit,
                'violating_user_id': user_id
            }
        )

    def log_suspicious_api_activity(self, endpoint: str, activity_type: str,
                                   details: Dict[str, Any]) -> None:
        """Log suspicious API activity."""
        self._log_security_event(
            event_type=self.SECURITY_EVENT,
            action="suspicious_api_activity",
            severity=self.HIGH,
            success=False,
            message=f"Suspicious API activity detected: {activity_type}",
            additional_data={
                'endpoint': endpoint,
                'activity_type': activity_type,
                'details': details
            }
        )

    # Data Access Events
    def log_sensitive_data_access(self, data_type: str, record_count: int,
                                 user_id: str = "", query_params: Dict[str, Any] = None) -> None:
        """Log access to sensitive data."""
        self._log_security_event(
            event_type=self.DATA_EVENT,
            action="sensitive_data_access",
            severity=self.MEDIUM,
            success=True,
            message=f"Sensitive data accessed: {data_type}",
            additional_data={
                'data_type': data_type,
                'record_count': record_count,
                'accessing_user_id': user_id,
                'query_params': query_params
            }
        )

    def log_data_export(self, data_type: str, export_format: str,
                       record_count: int, user_id: str = "") -> None:
        """Log data export operations."""
        self._log_security_event(
            event_type=self.DATA_EVENT,
            action="data_export",
            severity=self.HIGH,
            success=True,
            message=f"Data exported: {data_type} ({record_count} records)",
            additional_data={
                'data_type': data_type,
                'export_format': export_format,
                'record_count': record_count,
                'exporting_user_id': user_id
            }
        )

    # Administrative Events
    def log_admin_action(self, action: str, target: str, user_id: str = "",
                        additional_details: Dict[str, Any] = None) -> None:
        """Log administrative actions."""
        self._log_security_event(
            event_type=self.ADMIN_EVENT,
            action="admin_action",
            severity=self.HIGH,
            success=True,
            message=f"Administrative action performed: {action}",
            additional_data={
                'admin_action': action,
                'target': target,
                'performing_user_id': user_id,
                'details': additional_details
            }
        )

    def log_configuration_change(self, setting: str, old_value: str, new_value: str,
                                user_id: str = "") -> None:
        """Log configuration changes."""
        self._log_security_event(
            event_type=self.ADMIN_EVENT,
            action="configuration_change",
            severity=self.HIGH,
            success=True,
            message=f"Configuration changed: {setting}",
            additional_data={
                'setting': setting,
                'old_value': old_value[:100] if len(old_value) > 100 else old_value,
                'new_value': new_value[:100] if len(new_value) > 100 else new_value,
                'changing_user_id': user_id
            }
        )

    # Security Violation Events
    def log_input_validation_failure(self, field: str, value: str, validation_type: str) -> None:
        """Log input validation failures that might indicate attacks."""
        self._log_security_event(
            event_type=self.SECURITY_EVENT,
            action="input_validation_failure",
            severity=self.MEDIUM,
            success=False,
            message=f"Input validation failed for {field}",
            additional_data={
                'field': field,
                'rejected_value': value[:200] if len(value) > 200 else value,
                'validation_type': validation_type
            }
        )

    def log_csrf_attack_attempt(self, endpoint: str, expected_token: str, received_token: str) -> None:
        """Log CSRF attack attempts."""
        self._log_security_event(
            event_type=self.SECURITY_EVENT,
            action="csrf_attack_attempt",
            severity=self.HIGH,
            success=False,
            message=f"CSRF attack attempt detected on {endpoint}",
            additional_data={
                'endpoint': endpoint,
                'expected_token': expected_token[:8] + '...' if expected_token else None,
                'received_token': received_token[:8] + '...' if received_token else None
            }
        )

    def log_xss_attempt(self, field: str, payload: str) -> None:
        """Log XSS attack attempts."""
        self._log_security_event(
            event_type=self.SECURITY_EVENT,
            action="xss_attack_attempt",
            severity=self.HIGH,
            success=False,
            message=f"XSS attack attempt detected in {field}",
            additional_data={
                'field': field,
                'malicious_payload': payload[:200] if len(payload) > 200 else payload
            }
        )

    def log_sql_injection_attempt(self, field: str, payload: str) -> None:
        """Log SQL injection attempts."""
        self._log_security_event(
            event_type=self.SECURITY_EVENT,
            action="sql_injection_attempt",
            severity=self.CRITICAL,
            success=False,
            message=f"SQL injection attempt detected in {field}",
            additional_data={
                'field': field,
                'malicious_payload': payload[:200] if len(payload) > 200 else payload
            }
        )

    # System Events
    def log_system_startup(self, version: str, config_details: Dict[str, Any] = None) -> None:
        """Log system startup events."""
        self._log_security_event(
            event_type=self.SYSTEM_EVENT,
            action="system_startup",
            severity=self.LOW,
            success=True,
            message=f"OpenVPN Manager frontend started (version {version})",
            additional_data={
                'version': version,
                'config': config_details
            }
        )

    def log_system_error(self, error_type: str, error_message: str,
                        stack_trace: str = None) -> None:
        """Log system errors that might have security implications."""
        self._log_security_event(
            event_type=self.SYSTEM_EVENT,
            action="system_error",
            severity=self.MEDIUM,
            success=False,
            message=f"System error occurred: {error_type}",
            additional_data={
                'error_type': error_type,
                'error_message': error_message[:500] if len(error_message) > 500 else error_message,
                'stack_trace': stack_trace[:1000] if stack_trace and len(stack_trace) > 1000 else stack_trace
            }
        )

    def log_data_access(self, data_type: str, access_type: str, user_id: str = "",
                       additional_details: Dict[str, Any] = None) -> None:
        """Log access to sensitive data."""
        self._log_security_event(
            event_type=self.DATA_EVENT,
            action="data_access",
            severity=self.MEDIUM,
            success=True,
            message=f"Data access: {access_type} on {data_type}",
            additional_data={
                'data_type': data_type,
                'access_type': access_type,
                'accessing_user_id': user_id,
                'details': additional_details
            }
        )

    def log_certificate_bulk_revoked(self, revocation_type: str, target_identifier: str,
                                    reason: str, user_id: str = "", certificates_affected: int = 0) -> None:
        """Log bulk certificate revocation events."""
        self._log_security_event(
            event_type=self.CERT_EVENT,
            action="certificate_bulk_revoked",
            severity=self.HIGH,
            success=True,
            message=f"Bulk certificate revocation: {revocation_type}",
            additional_data={
                'revocation_type': revocation_type,
                'target_identifier': target_identifier,
                'revocation_reason': reason,
                'revoking_user_id': user_id,
                'certificates_affected': certificates_affected
            }
        )

    def log_psk_created(self, psk_type: str, description: str, template_set: str,
                       created_by: str = "", expires_at: str = None) -> None:
        """Log PSK creation events."""
        self._log_security_event(
            event_type=self.ADMIN_EVENT,
            action="psk_created",
            severity=self.MEDIUM,
            success=True,
            message=f"PSK created: {psk_type}",
            additional_data={
                'psk_type': psk_type,
                'description': description,
                'template_set': template_set,
                'created_by': created_by,
                'expires_at': expires_at
            }
        )


# Global security logger instance
security_logger = SecurityEventLogger()


def log_security_event(func):
    """
    Decorator to automatically log security events for function calls.

    Usage:
        @log_security_event
        def sensitive_function():
            pass
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        function_name = f"{func.__module__}.{func.__name__}"

        try:
            result = func(*args, **kwargs)
            security_logger._log_security_event(
                event_type=SecurityEventLogger.SYSTEM_EVENT,
                action="function_call",
                severity=SecurityEventLogger.LOW,
                success=True,
                message=f"Security-sensitive function called: {function_name}",
                additional_data={
                    'function': function_name,
                    'args_count': len(args),
                    'kwargs_keys': list(kwargs.keys())
                }
            )
            return result
        except Exception as e:
            security_logger._log_security_event(
                event_type=SecurityEventLogger.SYSTEM_EVENT,
                action="function_error",
                severity=SecurityEventLogger.MEDIUM,
                success=False,
                message=f"Error in security-sensitive function: {function_name}",
                additional_data={
                    'function': function_name,
                    'error_type': type(e).__name__,
                    'error_message': str(e)
                }
            )
            raise

    return wrapper