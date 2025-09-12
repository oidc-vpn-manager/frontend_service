/**
 * Bounce page endpoint validation JavaScript
 * Handles endpoint accessibility checks for both admin and user service bounces
 */

document.addEventListener('DOMContentLoaded', function () {
    // Get configuration from data attributes or global variables
    const bounceContainer = document.querySelector('.bounce-container');
    if (!bounceContainer) return;
    
    const targetUrl = bounceContainer.dataset.targetUrl;
    const serviceType = bounceContainer.dataset.serviceType || 'service';
    
    if (!targetUrl) {
        console.error('No target URL specified for endpoint validation');
        return;
    }
    
    const statusElement = document.getElementById('endpoint-status');
    const refreshMeta = document.getElementById('refresh-meta');
    const manualLink = document.getElementById('manual-link');
    
    function checkEndpoint() {
        if (!statusElement) return;
        
        // Extract base URL for health check
        let baseUrl;
        try {
            const url = new URL(targetUrl);
            baseUrl = url.origin;
        } catch (e) {
            console.error('Invalid target URL:', targetUrl);
            showInaccessible('Invalid target URL');
            return;
        }
        
        const healthUrl = baseUrl + '/health';
        const timeout = 5000; // 5 second timeout
        
        // Create abort controller for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        fetch(healthUrl, {
            method: 'GET',
            mode: 'cors',
            signal: controller.signal,
            headers: {
                'Accept': 'application/json'
            }
        })
        .then(response => {
            clearTimeout(timeoutId);
            if (response.ok) {
                return response.json();
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        })
        .then(data => {
            if (data && (data.status === 'ok' || data.status === 'healthy')) {
                showAccessible(`${serviceType} service is accessible - redirecting...`);
            } else {
                showInaccessible(`${serviceType} service responded but status unknown`);
            }
        })
        .catch(error => {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                showInaccessible(`${serviceType} service check timed out`);
            } else {
                console.error('Endpoint check failed:', error);
                showWarning(`Cannot verify ${serviceType} service - proceeding with redirect...`);
            }
        });
    }
    
    function showAccessible(message) {
        if (statusElement) {
            statusElement.textContent = message;
            statusElement.className = 'endpoint-check accessible';
        }
    }
    
    function showInaccessible(message) {
        if (statusElement) {
            statusElement.textContent = message + ' - Please use manual link below.';
            statusElement.className = 'endpoint-check inaccessible';
        }
        
        // Disable automatic redirect
        if (refreshMeta) {
            refreshMeta.content = '';
        }
    }
    
    function showWarning(message) {
        if (statusElement) {
            statusElement.textContent = message;
            statusElement.className = 'endpoint-check checking';
        }
        // Keep automatic redirect enabled
    }
    
    // Start endpoint check
    checkEndpoint();
});