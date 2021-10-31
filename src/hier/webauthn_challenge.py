"""
Functions for managing the webauthn `challenge`. Expects the challenge to be an alphanumeric str.
"""
import hmac
import hashlib

from werkzeug.exceptions import BadRequest

from .secrets import SECRET_KEY

# Name of cookie to use for storing the temporary challenge.
COOKIE_CHALLENGE = 'challenge'


def _sign(value: str) -> str:
    """Takes given value, signs it using HMAC with secret key, and returns a signature in hex.

    This mimics Flask's built-in signed session cookie.
    """
    return hmac.new(SECRET_KEY, msg=bytes(value, 'ascii'), digestmod=hashlib.sha256).hexdigest()


def set_challenge_cookie(resp, challenge: str):
    """Stores challenge cookie (carefully) for verification later.

    We could use the flask session instead (which is built-in and is signed), but I wanted a separate lifecycle for the
    challenge and limit it to a shorter duration. The most important requirement here is a guarantee that the challenge
    has not been tampered.

    Improvement: have the frontend flash an error message, or refresh the page, if challenge cookie has expired.
    """
    # sign challenge to prevent tampering
    signature = _sign(challenge)
    resp.set_cookie(COOKIE_CHALLENGE,
                    f'{challenge}+{signature}',
                    httponly=True,
                    secure=True,
                    max_age=6*60*60,
                    samesite='strict')


def validate_challenge_cookie(req) -> str:
    """Retrieves challenge from cookie (carefully).

    Checks signature to confirm integrity. Throws `InvalidWebAuthnChallenge` if the challenge is missing, tampered, or
    otherwise invalid.

    :return: challenge
    """
    if COOKIE_CHALLENGE not in req.cookies:
        raise InvalidWebAuthnChallenge(f'Missing {COOKIE_CHALLENGE} cookie.')
    signed_challenge = req.cookies[COOKIE_CHALLENGE]
    tokens = signed_challenge.split('+')

    if len(tokens) != 2:
        raise InvalidWebAuthnChallenge(f'Malformed {COOKIE_CHALLENGE} cookie.')
    challenge = tokens[0]
    signature = tokens[1]

    if hmac.compare_digest(signature, _sign(challenge)):
        return challenge
    else:
        raise InvalidWebAuthnChallenge(f'Malformed {COOKIE_CHALLENGE} cookie.')


class InvalidWebAuthnChallenge(BadRequest):
    description = "The webauthn challenge is invalid."
