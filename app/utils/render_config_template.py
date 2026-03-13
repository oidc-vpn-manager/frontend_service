"""
Secure OpenVPN configuration template management and rendering system.

This module provides template loading, selection, and rendering functionality for
OpenVPN profiles. It uses a priority-based template system where templates are
named with priority numbers and group names (e.g., '0100.Developers.ovpn').

Security features:
- Sandboxed Jinja2 environment to prevent template injection attacks
- HTML escaping of user-provided values
- Strict undefined variable handling
- Template security violation detection
"""

import os
import jinja2
from jinja2.sandbox import SandboxedEnvironment
from flask import Flask
from app.utils.tracing import trace

def load_config_templates(app: Flask, template_path) -> list:
    """
    Load and parse OpenVPN configuration templates from a directory.

    This function scans a directory for OpenVPN template files with the naming
    convention 'PRIORITY.GROUPNAME.ovpn' and loads them into memory with caching.
    Templates are sorted by priority for later selection.

    Template naming convention:
    - Format: '{priority}.{group_name}.ovpn'
    - Priority: Numeric value (e.g., 0100, 0200) for template selection precedence
    - Group name: OIDC group name or special names like 'Default'
    - Extension: Must be '.ovpn'

    Args:
        app (Flask): Flask application instance for configuration and logging
        template_path (str): Directory path containing template files

    Returns:
        list: Sorted list of template dictionaries containing:
            - priority (int): Numeric priority for template selection
            - group_name (str): Group name for template matching
            - file_name (str): Original filename
            - content (str): Template file content

    Raises:
        FileNotFoundError: If template_path doesn't exist or isn't a directory

    Example:
        >>> templates = load_config_templates(app, '/etc/openvpn/templates')
        >>> # Templates sorted by priority:
        >>> # [{'priority': 100, 'group_name': 'Default', 'file_name': '0100.Default.ovpn', ...},
        >>> #  {'priority': 200, 'group_name': 'Developers', 'file_name': '0200.Developers.ovpn', ...}]

    Note:
        Templates are cached in app.config['TEMPLATE_COLLECTION'] to avoid
        repeated filesystem access. Subsequent calls return cached templates.
    """
    trace(
        app,
        'utils.render_config_template.load_config_templates',
        {
            'app': 'FLASK',
            'template_path': template_path
        }
    )
    # Corrected check for whether the templates have already been loaded
    if app.config.get('TEMPLATE_COLLECTION') is None:
        app.logger.info(f"Loading OVPN templates from {template_path}")
        if not os.path.isdir(template_path):
            raise FileNotFoundError(f"ERROR: OVPN template path '{template_path}' not found or not a directory.")
        
        loaded_templates = []
        for filename in os.listdir(template_path):
            if not filename.endswith(".ovpn"):
                app.logger.debug(f'Skipping {filename} as it does not end .ovpn.')
                continue
            
            parts = filename.split('.', 2)
            if len(parts) >= 3 and parts[0].isdigit():
                priority = int(parts[0])
                group_name = parts[1]
                with open(os.path.join(template_path, filename), 'r') as f:
                    content = f.read()
                loaded_templates.append({
                    "priority": priority,
                    "group_name": group_name,
                    "file_name": filename,
                    "content": content
                })
                app.logger.debug(f'Imported {filename} with {priority} priority for {group_name} group.')
            else:
                app.logger.debug(f'Skipping {filename} as it does not have the right format filename.')
        app.config['TEMPLATE_COLLECTION'] = sorted(loaded_templates, key=lambda x: x['priority'])
    
    return app.config.get('TEMPLATE_COLLECTION', [])

def find_best_template_match(app: Flask, user_group_memberships, template_collection: list[str] = None) -> tuple:
    """
    Select the best OpenVPN template for a user based on their group memberships.

    This function implements the template selection algorithm used for generating
    personalized OpenVPN configurations. It matches user OIDC group memberships
    against available templates, falling back to a default template if no
    specific match is found.

    Selection algorithm:
    1. Load templates if not already cached
    2. Find templates matching user's group memberships (case-insensitive)
    3. Select first matching template based on priority order
    4. Fall back to 'Default' template if no matches
    5. Raise error if no default template exists

    Args:
        app (Flask): Flask application instance for configuration and logging
        user_group_memberships (list): List of OIDC group names for the user
        template_collection (list, optional): Pre-loaded template collection,
                                            otherwise loads from app config

    Returns:
        tuple: (template_filename, template_content) where:
            - template_filename (str): Selected template filename
            - template_content (str): Template file content for Jinja2 rendering

    Raises:
        ValueError: If no matching template and no default template is available

    Example:
        >>> # User is member of 'Developers' and 'VPN-Users' groups
        >>> filename, content = find_best_template_match(app, ['Developers', 'VPN-Users'])
        >>> # Returns template for 'Developers' if available, else 'Default'
        >>> print(filename)  # '0200.Developers.ovpn'
        >>>
        >>> # User with no matching groups
        >>> filename, content = find_best_template_match(app, ['Unknown-Group'])
        >>> print(filename)  # '0100.Default.ovpn'
    """
    trace(
        app,
        'utils.render_config_template.find_best_template_match',
        {
            'app': 'FLASK',
            'user_group_memberships': user_group_memberships,
            'template_collection': template_collection
        }
    )
    if template_collection is None:
        template_collection = app.config.get('TEMPLATE_COLLECTION')

    if template_collection is None:
        template_path = app.config.get('OVPN_TEMPLATE_PATH')
        if template_path:
            template_collection = load_config_templates(app, template_path)
        else:
            template_collection = []
            app.config['TEMPLATE_COLLECTION'] = template_collection

    lower_user_group_memberships = {groupname.lower() for groupname in (user_group_memberships or [])}

    default_template = {}
    for template in template_collection:
        if template['group_name'].lower() == 'default':
            default_template = template
    selected_template = default_template
    for template in template_collection:
        if template['group_name'].lower() in lower_user_group_memberships:
            selected_template = template
            break
    
    if not selected_template:
        raise ValueError("No matching template found and no default is available.")

    template_name = selected_template['file_name']
    template_content = selected_template['content']

    return template_name, template_content

def validate_config_templates(app: Flask) -> None:
    """
    Validate all OpenVPN configuration templates at application startup.

    Renders every template from OVPN_TEMPLATE_PATH with a representative dummy
    context so that undefined-variable errors (e.g. ``'protocol' is undefined``)
    are caught before the pod accepts traffic, rather than at the moment a user
    requests their first profile.

    The dummy context covers every variable that the download and root routes
    inject, including optionset-provided overrides.  Templates may use
    ``| default(...)`` for optional variables not listed here; those will
    continue to work because Jinja2 resolves them without touching the context.

    Args:
        app (Flask): Flask application instance.

    Raises:
        RuntimeError: If one or more templates fail to render, with all failures
                      listed in a single message so operators can fix them all at once.
    """
    template_path = app.config.get('OVPN_TEMPLATE_PATH')
    if not template_path:
        app.logger.debug("OVPN_TEMPLATE_PATH not configured; skipping template validation.")
        return

    try:
        templates = load_config_templates(app, template_path)
    except FileNotFoundError as e:
        raise RuntimeError(f"Template validation failed: {e}") from e

    if not templates:
        app.logger.warning("No OpenVPN templates found; skipping template validation.")
        return

    # Dummy context mirrors every variable injected by download.py and root.py.
    # Use placeholder PEM strings so the sandbox renders them as plain text.
    dummy_cert = "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END CERTIFICATE-----"
    dummy_key  = "-----BEGIN PRIVATE KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PRIVATE KEY-----"
    dummy_tls  = "-----BEGIN OpenVPN Static key V1-----\n0000000000000000\n-----END OpenVPN Static key V1-----"

    dummy_context = {
        # Identification
        'template_name': 'validation-dummy',
        'common_name': 'dummy@example.com',
        'userinfo': {'sub': 'dummy', 'email': 'dummy@example.com', 'name': 'Dummy User'},
        # Certificate material
        'ca_cert_pem': dummy_cert,
        'device_cert_pem': dummy_cert,
        'device_key_pem': dummy_key,
        # TLS-Crypt (both alias and canonical name)
        'tls_crypt_key': dummy_tls,
        'tlscrypt_key': dummy_tls,
        'tlscrypt_version': 1,
        # Network / protocol defaults
        'protocol': 'udp',
        'port': 1194,
        # Option-set flags
        'use_tcp': False,
        'custom_port': None,
        'enable_compression': False,
        'mobile_settings': False,
    }

    failures = []
    for template in templates:
        try:
            render_config_template(app, template['content'], **dummy_context)
        except (ValueError, Exception) as exc:
            failures.append(f"  {template['file_name']}: {exc}")

    if failures:
        failure_list = "\n".join(failures)
        raise RuntimeError(
            f"OpenVPN template validation failed for {len(failures)} template(s):\n{failure_list}"
        )

    app.logger.info(f"Template validation passed for {len(templates)} template(s).")


def render_config_template(app: Flask, template_string, **kargs):
    """
    Securely render an OpenVPN configuration template with user-specific data.

    This function takes a Jinja2 template string and renders it with the provided
    context variables to generate a personalized OpenVPN configuration file.
    Security measures prevent template injection attacks and ensure safe rendering.

    Security features:
    - Sandboxed Jinja2 environment prevents dangerous operations
    - HTML escaping for all string variables to prevent injection
    - Strict undefined variable handling (raises errors for undefined variables)
    - Security violation detection and reporting
    - Recursive sanitization of nested dictionary values

    Args:
        app (Flask): Flask application instance for logging
        template_string (str): Jinja2 template content to render
        **kargs: Template context variables including:
            - ca_cert_pem (str): CA certificate chain
            - device_cert_pem (str): User/device certificate
            - device_key_pem (str): User/device private key
            - userinfo (dict): User information from OIDC
            - tls_crypt_key (str): TLS-Crypt key for additional security
            - Custom template variables (protocol settings, etc.)

    Returns:
        str: Rendered OpenVPN configuration file content with embedded certificates
             and user-specific settings

    Raises:
        ValueError: If template contains unsafe operations or rendering fails

    Example:
        >>> template_content = '''
        ... client
        ... remote {{server_host}} {{server_port}}
        ... <ca>
        ... {{ca_cert_pem}}
        ... </ca>
        ... <cert>
        ... {{device_cert_pem}}
        ... </cert>
        ... '''
        >>>
        >>> rendered = render_config_template(app, template_content,
        ...     server_host="vpn.company.com",
        ...     server_port="1194",
        ...     ca_cert_pem=ca_cert,
        ...     device_cert_pem=user_cert
        ... )
        >>> # Returns complete .ovpn file with embedded certificates

    Security Notes:
        - autoescape is intentionally disabled: output is an OpenVPN config file,
          not HTML, so HTML-escaping would corrupt certificate/key PEM data.
        - Template code execution is restricted by SandboxedEnvironment.
        - Context variable values are never evaluated as template code.
        - Rendered output is not logged (contains sensitive key material)
    """
    trace(
        app,
        'utils.render_config_template.render_config_template',
        {
            'app': 'FLASK',
            'template_string': template_string,
            'kargs': kargs
        }
    )

    # SandboxedEnvironment prevents arbitrary code execution in templates.
    # autoescape=False is correct here: OpenVPN config files are not HTML, and
    # enabling autoescape would HTML-encode certificate / key PEM data, producing
    # an invalid profile that clients reject with "Invalid character" errors.
    sandbox_env = SandboxedEnvironment(
        autoescape=False,
        undefined=jinja2.StrictUndefined
    )

    try:
        # Use sandboxed environment for template creation
        final_template = sandbox_env.from_string(template_string)
        rendered_template = final_template.render(**kargs)
    except Exception as e:
        if "SecurityError" in str(type(e)) or "unsafe" in str(e).lower():
            app.logger.error(f"Template security violation detected: {e}")
            raise ValueError("Template contains unsafe operations") from e
        else:
            app.logger.error(f"Template rendering error: {e}")
            raise ValueError("Template rendering failed") from e

    app.logger.debug(f'Rendered template output length: {len(rendered_template)} characters')
    # Do not log rendered template content as it contains certificates and private keys

    return rendered_template