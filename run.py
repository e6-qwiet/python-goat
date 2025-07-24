from flask_webgoat import create_app

app = create_app()

@app.after_request
def add_csp_headers(response):
def add_csp_headers(response, inline_scripts=None, inline_styles=None):
    # vulnerability: Broken Access Control - fixed by restricting CORS
    response.headers['Access-Control-Allow-Origin'] = 'https://trusted-origin.com'
    
    # Generate nonce for dynamic inline scripts
    nonce = secrets.token_hex(16)
    
    # Initialize CSP parts
    script_src = f"'self' 'nonce-{nonce}' 'strict-dynamic'"
    style_src = "'self'"
    
    # Add script hashes if provided
    if inline_scripts:
        for script in inline_scripts:
            script_hash = f"'sha256-{hashlib.sha256(script.encode()).hexdigest()}'"
            script_src += f" {script_hash}"
    
    # Add style hashes if provided
    if inline_styles:
        for style in inline_styles:
            style_hash = f"'sha256-{hashlib.sha256(style.encode()).hexdigest()}'"
            style_src += f" {style_hash}"
    
    # Comprehensive CSP that implements all mitigation notes
    csp = (
        f"default-src 'self'; "
        f"script-src {script_src}; "
        f"style-src {style_src}; "
        f"img-src 'self' data:; "
        f"font-src 'self'; "
        f"object-src 'none'; "
        f"base-uri 'self'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none'; "
        f"block-all-mixed-content; "
        f"upgrade-insecure-requests; "
        f"report-uri /csp-violation-report-endpoint"
    )
    
    # Set security headers
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Implement Permissions-Policy to restrict powerful features
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=(), payment=()'
    
    # Return both response and nonce so it can be used in templates for dynamic scripts
    return response, nonce, {
        'script_nonce': nonce,
        'script_hashes': [hashlib.sha256(script.encode()).hexdigest() for script in (inline_scripts or [])]
    }

    app.run()
