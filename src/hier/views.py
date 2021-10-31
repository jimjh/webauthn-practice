import secrets
import json
import base64
import urllib3

import webauthn.helpers.structs
from flask import Blueprint, Response
from flask import render_template, make_response, request, jsonify, abort, redirect, url_for
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidAuthenticationResponse
from werkzeug.exceptions import BadRequest
from webauthn.helpers.structs import RegistrationCredential, AuthenticationCredential

from hier import webauthn_challenge as chl
from hier.controllers import user_controller

ORIGIN = 'http://localhost:5000'

blueprint = Blueprint("public", __name__, static_folder="../static")


@blueprint.route("/")
def hello_world():
    return "<p>Hello World!</p>"


@blueprint.route("/hash_user_id")
def hash_user_id():
    """Converts user name to user ID.

    Decision: implement on server-side to guarantee consistency. Also allows the server to
    change the implementation in the future while maintaining backwards compatibility.

    Decision: we need to hash user names, instead of using unique user names directly, because
    their keyspaces are different.
    - user id: 64 bytes
    - user name: unicode string

    Note that since the user ID generation is deterministic (given user name), this does not
    involve a round trip to the database, and does not leak any information about our existing
    users.
    """
    user_name = request.args.get('user_name')  # type: str
    if user_name is None or len(user_name) <= 0:
        raise BadRequest('Missing user_name parameter.')

    return jsonify(user_controller.hash_user_id(user_name))


@blueprint.route("/register", methods=['GET', 'PUT'])
def register():
    """Renders registration page, creates user, and binds credentials.

    Decision: skip the python webauthn library when generating the creation options, since it doesn't seem practical
    that we would know the username and user ID a priori. Sending another round-trip and form submission feels like
    overkill for what I am trying to learn here.

    Input: desired user name, generated user ID, authenticator

    Fork in the Road: if we choose to only trust a few select authenticator manufacturers,
    we can rely on the hardware token's proof of presence. If we choose to trust all authenticators,
    then we need some sort of rate limiter (captcha) to defend against username harvesting.
    """
    if request.method == 'PUT':
        user = _create_user(request)
        return jsonify(user)
    else:
        # 16 bytes, as per https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
        challenge = secrets.token_hex(16)
        resp = make_response(render_template('register.html', challenge=challenge))
        chl.set_challenge_cookie(resp, challenge)
        return resp


def _create_user(req):
    """
    Algorithm:
      1. Validate challenge.
      2. Validate authenticator.
      3. Business logic.
    """
    challenge = chl.validate_challenge_cookie(req)  # type: str
    posted_data = req.get_json()

    for key in ('userId', 'userName', 'displayName'):
        if key not in posted_data or len(posted_data[key]) <= 0:
            raise BadRequest(f'Missing {key}.')

    user_id = bytes(posted_data['userId'], 'ascii')
    user_name = posted_data['userName']
    display_name = posted_data['displayName']

    try:
        credential = RegistrationCredential.parse_raw(req.data)  # type: RegistrationCredential
    except ValidationError as e:
        raise BadRequest('Malformed registration credential.') from e

    try:
        verified_registration = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge.encode('ascii'),
            expected_origin=ORIGIN,
            expected_rp_id=_rp_id_from_origin(ORIGIN)
        )
    except InvalidRegistrationResponse as e:
        raise BadRequest('Malformed registration credential.') from e

    try:
        return user_controller.create_user(user_id, user_name, display_name, verified_registration)
    except IntegrityError:
        raise DuplicateUserError()


def _rp_id_from_origin(origin: str) -> str:
    return urllib3.util.parse_url(origin).host


@blueprint.route('/credentials', methods=['GET'])
def credentials():
    """Lists the credential IDs of the given user."""
    user_name = request.args.get('user_name')  # type: str
    if user_name is None or len(user_name) <= 0:
        raise BadRequest('Missing user_name parameter.')
    # TODO return fake credentials if user does not exist
    creds = user_controller.list_credentials(user_name)
    return jsonify([str(base64.b64encode(cred), 'ascii') for cred in creds])


@blueprint.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return _verify_credential(request)
    else:
        # 16 bytes, as per https://w3c.github.io/webauthn/#sctn-cryptographic-challenges
        challenge = secrets.token_hex(16)
        resp = make_response(render_template('login.html', challenge=challenge))
        chl.set_challenge_cookie(resp, challenge)
        return resp


def _verify_credential(req):
    """
    Algorithm:
      1. Validate challenge.
      2. Verify credential by looking up user ID and credential ID.
      3. Update sign count if found.
    """
    challenge = chl.validate_challenge_cookie(req)  # type: str
    posted_data = req.get_json()

    for key in ('userName',):
        if key not in posted_data or len(posted_data[key]) <= 0:
            raise BadRequest(f'Missing {key}.')

    user_name = posted_data['userName']

    try:
        submitted_credential = AuthenticationCredential.parse_raw(req.data)
    except ValidationError as e:
        raise BadRequest("Malformed authentication credentials.") from e

    # lookup credential and user, returning a 404 if not found
    credential_id = submitted_credential.raw_id
    target_credential = user_controller.find_by_user_name_and_credential_id(user_name, credential_id)
    if target_credential is None:
        error = json.dumps({'message': f'no such user+credential combination: {user_name}'})
        abort(Response(error, 404))

    try:
        verification = webauthn.verify_authentication_response(
            credential=submitted_credential,
            expected_challenge=challenge.encode('ascii'),
            expected_origin=ORIGIN,
            expected_rp_id=_rp_id_from_origin(ORIGIN),
            credential_public_key=target_credential.credential_public_key,
            credential_current_sign_count=target_credential.sign_count
        )
    except InvalidAuthenticationResponse as e:
        raise BadRequest("Invalid authentication credentials.") from e

    # This can be moved into a background thread and executed probabilistically in case of txn contention.
    user_controller.update_sign_count(target_credential.id, verification.new_sign_count)
    return verification.json()


class DuplicateUserError(BadRequest):
    description = "User exists. Send them over to /login instead."
