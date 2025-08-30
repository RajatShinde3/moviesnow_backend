from datetime import datetime
from sqlalchemy import Column, String, Integer, ForeignKey, LargeBinary, DateTime
from sqlalchemy.orm import relationship, validates
from app.db.base_class import Base
from app.db.models.user import User

class WebAuthnCredential(Base):
    """
    WebAuthnCredential Model
    ========================
    This model represents WebAuthn credentials stored for users.
    It tracks each credential's metadata and security attributes for 
    authentication and registration purposes.

    Attributes
    ----------
    id : int
        Unique identifier for the WebAuthn credential.
    user_id : int
        Foreign key linking to the User table, identifying the user this credential belongs to.
    credential_id : str
        Unique identifier of the credential, usually generated during registration.
    public_key : bytes
        The public key associated with this WebAuthn credential.
    sign_count : int
        A counter used to track the number of times the credential has been used in authentication.
    transports : str
        A string describing the types of transports supported by the WebAuthn device (e.g., USB, NFC).
    created_at : datetime
        The timestamp when this credential was registered.
    last_used_at : datetime
        The timestamp when this credential was last used in authentication.

    Relationships
    -------------
    user : User
        A relationship to the User table, indicating which user this credential belongs to.
    """

    __tablename__ = "webauthn_credentials"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    credential_id = Column(String(255), nullable=False, unique=True)
    public_key = Column(LargeBinary, nullable=False)
    sign_count = Column(Integer, default=0, nullable=False)
    transports = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = Column(DateTime, default=datetime.utcnow, nullable=True)

    user = relationship("User", back_populates="webauthn_credentials")

    # Validations
    @validates("credential_id")
    def validate_credential_id(self, key, value):
        """
        Ensures the credential_id is a valid, non-empty string.
        """
        if not value or len(value.strip()) == 0:
            raise ValueError("Credential ID must be a non-empty string.")
        return value.strip()

    @validates("public_key")
    def validate_public_key(self, key, value):
        """
        Ensures the public_key is not empty and is a valid binary string.
        """
        if not value or len(value) == 0:
            raise ValueError("Public key must be a non-empty binary string.")
        return value

    def __repr__(self):
        """
        Returns a string representation of the WebAuthn credential.
        """
        return f"<WebAuthnCredential(credential_id={self.credential_id}, user_id={self.user_id})>"

    def mark_as_used(self):
        """
        Mark the WebAuthn credential as used by updating the sign_count 
        and last_used_at timestamp.
        """
        self.sign_count += 1
        self.last_used_at = datetime.utcnow()

    def reset_sign_count(self):
        """
        Resets the sign_count to zero. This method can be used for specific actions like 
        unblocking a credential or other internal processes.
        """
        self.sign_count = 0
        self.last_used_at = datetime.utcnow()

    @classmethod
    def get_active_credentials_for_user(cls, session, user_id):
        """
        Returns all active WebAuthn credentials for a given user.
        """
        return session.query(cls).filter_by(user_id=user_id).all()

    @classmethod
    def get_by_credential_id(cls, session, credential_id):
        """
        Retrieves a WebAuthn credential by its credential_id.
        """
        return session.query(cls).filter_by(credential_id=credential_id).first()

    @classmethod
    def delete_by_credential_id(cls, session, credential_id):
        """
        Deletes a WebAuthn credential by its credential_id.
        """
        credential = cls.get_by_credential_id(session, credential_id)
        if credential:
            session.delete(credential)
            session.commit()
            return True
        return False
