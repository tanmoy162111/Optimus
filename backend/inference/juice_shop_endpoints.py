"""
OWASP Juice Shop Endpoint Database
Contains known vulnerable endpoints for comprehensive testing
"""

JUICE_SHOP_ENDPOINTS = {
    # SQL Injection vulnerable endpoints
    'sql_injection': [
        '/rest/products/search?q=',
        '/rest/user/login',
    ],
    
    # XSS vulnerable endpoints
    'xss': [
        '/rest/products/search?q=<script>',
        '/#/track-result?id=',
        '/#/search?q=',
    ],
    
    # API endpoints
    'api': [
        '/api/Users/',
        '/api/Products/',
        '/api/Feedbacks/',
        '/api/Complaints/',
        '/api/Recycles/',
        '/api/SecurityQuestions/',
        '/api/Challenges/',
        '/api/Quantitys/',
        '/api/Deliverys/',
        '/api/Addresss/',
        '/api/Cards/',
        '/api/Memorys/',
    ],
    
    # REST endpoints
    'rest': [
        '/rest/user/login',
        '/rest/user/reset-password',
        '/rest/user/change-password',
        '/rest/user/whoami',
        '/rest/basket/',
        '/rest/products/search?q=',
        '/rest/saveLoginIp',
        '/rest/deluxe-membership',
        '/rest/repeat-notification',
        '/rest/continue-code',
        '/rest/chatbot/status',
    ],
    
    # File upload/download
    'file': [
        '/file-upload',
        '/ftp/',
        '/assets/public/images/',
    ],
    
    # B2B API
    'b2b': [
        '/b2b/v2/orders',
    ],
    
    # Redirect endpoints
    'redirect': [
        '/redirect?to=',
    ],
}

def get_testable_urls(base_url: str) -> list:
    """Get all testable URLs for Juice Shop"""
    urls = []
    for category, endpoints in JUICE_SHOP_ENDPOINTS.items():
        for endpoint in endpoints:
            urls.append(f"{base_url.rstrip('/')}{endpoint}")
    return urls

def get_sql_injection_urls(base_url: str) -> list:
    """Get SQL injection testable URLs"""
    return [
        f"{base_url}/rest/products/search?q=test",
        f"{base_url}/rest/user/login",
    ]

def get_xss_urls(base_url: str) -> list:
    """Get XSS testable URLs"""
    return [
        f"{base_url}/rest/products/search?q=<test>",
        f"{base_url}/#/search?q=test",
    ]
