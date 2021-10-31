from sqlalchemy import ForeignKey, update
from sqlalchemy.orm import relationship

from hier.extensions import db


class Credential(db.Model):
    """
    A user has one or more credentials. This table only supports WebAuthn credentials.
    """

    # id: auto-incrementing unique key in database
    id = db.Column(db.Integer(), primary_key=True)

    # credential_id: generated credential's ID (at most 1023 bytes)
    credential_id = db.Column(db.BINARY(1023), nullable=False)

    # credential_public_key: generated credential's public key
    credential_public_key = db.Column(db.LargeBinary(), nullable=False)

    # sign_count: how many times the authenticator says the credential was used
    sign_count = db.Column(db.Integer(), nullable=False)

    # aaguid: A 128-bit identifier indicating the type and vendor of the authenticator
    aaguid = db.Column(db.String(32))

    # foreign key
    user_id = db.Column(db.String(64), ForeignKey('user.id'), nullable=False)
    user = relationship("User", back_populates="credentials")

    def __repr__(self):
        return f'<Credential {self.id!r}>'

    @staticmethod
    def update_sign_count_for_id(credential_id: int, sign_count: int):
        return update(Credential).where(Credential.id == credential_id).values(sign_count=sign_count)
