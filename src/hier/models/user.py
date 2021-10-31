from sqlalchemy.orm import relationship
from sqlalchemy import select

from hier.extensions import db
from .credential import Credential


class User(db.Model):
    """
    Decision:
    - require both user name and user ID to be unique
    - user ID is generated before inserting into the table

    Reason: so we don't have to pre-insert a row ahead of time when using webauthn, which
    requires a user ID for the authenticator to generate a credential.
    """

    # id: unique key in the database (submitted by user)
    id = db.Column(db.String(64), primary_key=True)

    # name: unique user name, chosen by the user, as per webauthn specifications
    name = db.Column(db.Unicode(256), nullable=False, unique=True)

    # display_name: as per webauthn specifications
    display_name = db.Column(db.Unicode(256), nullable=False)

    credentials = relationship("Credential", back_populates="user")

    def __repr__(self):
        return f'<User {self.name!r}>'

    @staticmethod
    def find_credentials_by_user_name(name):
        return select(Credential.credential_id).join(User.credentials).where(User.name == name)

    @staticmethod
    def find_credentials_by_user_name_and_credential_id(name, credential_id):
        return select(Credential.id, Credential.credential_public_key, Credential.sign_count)\
            .join(User.credentials).where(User.name == name, Credential.credential_id == credential_id)
