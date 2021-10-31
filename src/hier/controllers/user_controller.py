import hashlib
from webauthn.registration.verify_registration_response import VerifiedRegistration

from ..models.user import User
from ..models.credential import Credential
from ..extensions import db


def create_user(user_id: bytes,
                user_name: str,
                display_name: str,
                verified_registration: VerifiedRegistration):
    """Creates user and binds with given credential.

    Check if user_name and user_id are both unique. If so, create user record and credential record.
    """
    user = User(id=user_id, name=user_name, display_name=display_name)
    with db.session.begin():
        db.session.add(user)
        db.session.commit()

    # Deliberately insert credential in a separate txn, so that we have a chance to contact the user
    # via a follow-up email to retry if necessary, which mimics real-world flows (multi-step onboarding).
    credential = Credential(credential_id=verified_registration.credential_id,
                            credential_public_key=verified_registration.credential_public_key,
                            sign_count=verified_registration.sign_count,
                            aaguid=verified_registration.aaguid)
    with db.session.begin():
        user.credentials.append(credential)
        db.session.add(credential)
        db.session.commit()

    return {'id': user_id.decode('ascii'), 'name': user_name, 'display_name': display_name}


def hash_user_id(user_name: str) -> str:
    """Returns a deterministic 64-byte user ID from given user name."""

    # produce a 32-byte hash
    hashed = hashlib.sha256(user_name.encode('utf-8'))

    # convert to 64-byte string (having a index-able and printable user ID is valuable)
    user_id = hashed.hexdigest()
    assert len(user_id) == 64
    return user_id  # unfortunately the `bytes` type is not easily serializable in Python, so let's use a str


def list_credentials(user_name: str):
    result = db.session.execute(User.find_credentials_by_user_name(user_name))
    credentials = result.scalars().all()
    return credentials


def find_by_user_name_and_credential_id(user_name: str, credential_id: bytes):
    with db.session.begin():
        result = db.session.execute(User.find_credentials_by_user_name_and_credential_id(user_name, credential_id))
        return result.first()


def update_sign_count(credential_id: int, new_sign_count: int):
    with db.session.begin():
        db.session.execute(Credential.update_sign_count_for_id(credential_id, new_sign_count))
        db.session.commit()
