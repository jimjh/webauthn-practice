"""Global secrets for our Flask app.

In a production app, these would be kept in vaults and loaded into memory when the process starts.
"""

SECRET_KEY = b'd5d6ac7971ea75584c7cfa390f7a9c596e0a81ee0647799068aa33a4755ab84d'
DATABASE_URI = 'sqlite:////home/j/workspace/webauthn-practice/test.db'
