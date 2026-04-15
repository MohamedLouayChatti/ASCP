"""
Local-only secret fixtures for dlp_demo.py.

How to use:
1) Copy this file to dlp_demo_secrets.py
2) Edit values in dlp_demo_secrets.py with local test-only secret-like strings
3) Run python dlp_demo.py

Important:
- dlp_demo_secrets.py is gitignored and must never be committed.
- Keep this example file free of real secret signatures so push protection is never triggered.
"""

# Provide local values in dlp_demo_secrets.py.
# These example placeholders are intentionally non-secret-like.
DLP_DEMO_PAYMENT_GATEWAY_KEY = "LOCAL_TEST_PAYMENT_GATEWAY_KEY"
DLP_DEMO_STRIPE_API_KEY = "LOCAL_TEST_STRIPE_API_KEY"
DLP_DEMO_STRIPE_WEBHOOK_SECRET = "LOCAL_TEST_STRIPE_WEBHOOK_SECRET"
DLP_DEMO_STRIPE_SECRET_KEY = "LOCAL_TEST_STRIPE_SECRET_KEY"
