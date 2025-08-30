from datetime import datetime
from sqlalchemy import Column, String, Integer, ForeignKey, LargeBinary, DateTime
from sqlalchemy.orm import relationship, validates
from app.db.base_class import Base
from uuid import uuid4
from sqlalchemy.dialects.postgresql import UUID
class WebAuthnCredential(Base):
    """
    WebAuthnCredential Model
    ========================
    Represents the WebAuthn credentials stored for users. It tracks each credential's metadata and 
    security attributes for authentication and registration purposes, such as credential ID, public key,
    sign count, and transport mechanisms.

    Attributes
    ----------
    id : UUID
        Unique identifier for the WebAuthn credential, automatically generated.
    user_id : UUID
        Foreign key linking to the `users` table, identifying the user this credential belongs to.
    credential_id : str
        Unique identifier for the credential, typically generated during the registration process.
    public_key : bytes
        The public key associated with this WebAuthn credential.
    sign_count : int
        A counter that tracks the number of times the credential has been used in authentication.
    transports : str
        A string describing the types of transports supported by the WebAuthn device (e.g., USB, NFC).
    created_at : datetime
        Timestamp when the credential was registered.
    last_used_at : datetime
        Timestamp when the credential was last used in authentication.

    Relationships
    -------------
    user : User
        A relationship to the `User` table, indicating which user this credential belongs to.

    Methods
    -------
    mark_as_used:
        Updates the sign count and the `last_used_at` timestamp when the credential is used.
    reset_sign_count:
        Resets the sign count to zero, typically used in specific actions like unblocking a credential.
    get_active_credentials_for_user:
        Retrieves all active WebAuthn credentials for a specific user.
    get_by_credential_id:
        Retrieves a WebAuthn credential by its unique credential ID.
    delete_by_credential_id:
        Deletes a WebAuthn credential by its unique credential ID.
    """

    __tablename__ = "webauthn_credentials"

    # Primary Key: A unique UUID identifier for the WebAuthn credential.
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid4)    
    # Foreign Key: Links to the 'users' table, identifying the user this credential is associated with.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    # Unique credential identifier generated during registration.
    credential_id = Column(String(255), nullable=False, unique=True)
    
    # Public key associated with the WebAuthn credential.
    public_key = Column(LargeBinary, nullable=False)
    
    # Sign count tracks the number of uses for this credential.
    sign_count = Column(Integer, default=0, nullable=False)
    
    # Transports describe how the WebAuthn device can be accessed (e.g., USB, NFC).
    transports = Column(String(255), nullable=True)
    
    # Timestamp indicating when this credential was registered.
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    # Timestamp indicating the last use of this credential.
    last_used_at = Column(DateTime, default=datetime.utcnow, nullable=True)

    # Relationship with the User model.
    user = relationship("User", back_populates="webauthn_credentials")

    # Validations for fields to ensure proper data integrity.
    @validates("credential_id")
    def validate_credential_id(self, key, value):
        """
        Validates the `credential_id` to ensure it is a non-empty string.

        Parameters
        ----------
        key : str
            The field name (credential_id).
        value : str
            The value to be validated.

        Returns
        -------
        str
            The cleaned `credential_id` (non-empty).
        
        Raises
        ------
        ValueError
            If the `credential_id` is empty or just whitespace.
        """
        if not value or len(value.strip()) == 0:
            raise ValueError("Credential ID must be a non-empty string.")
        return value.strip()

    @validates("public_key")
    def validate_public_key(self, key, value):
        """
        Validates the `public_key` to ensure it is a non-empty binary string.

        Parameters
        ----------
        key : str
            The field name (public_key).
        value : bytes
            The value to be validated.

        Returns
        -------
        bytes
            The validated `public_key`.

        Raises
        ------
        ValueError
            If the `public_key` is empty or not valid.
        """
        if not value or len(value) == 0:
            raise ValueError("Public key must be a non-empty binary string.")
        return value

    def __repr__(self):
        """
        Returns a string representation of the WebAuthn credential.

        Returns
        -------
        str
            A string that includes `credential_id` and `user_id`.
        """
        return f"<WebAuthnCredential(credential_id={self.credential_id}, user_id={self.user_id})>"

    def mark_as_used(self):
        """
        Marks the WebAuthn credential as used by updating the `sign_count` 
        and the `last_used_at` timestamp to the current time.

        This method is typically called when the credential is used in authentication.

        Returns
        -------
        None
        """
        self.sign_count += 1
        self.last_used_at = datetime.utcnow()

    def reset_sign_count(self):
        """
        Resets the sign count to zero and updates the `last_used_at` timestamp.

        This method is used for actions like unblocking a credential.

        Returns
        -------
        None
        """
        self.sign_count = 0
        self.last_used_at = datetime.utcnow()

    @classmethod
    def get_active_credentials_for_user(cls, session, user_id):
        """
        Retrieves all active WebAuthn credentials for a given user.

        Parameters
        ----------
        session : AsyncSession
            The SQLAlchemy session used for querying the database.
        user_id : UUID
            The ID of the user whose active credentials are being fetched.

        Returns
        -------
        list
            A list of WebAuthnCredential objects associated with the user.
        """
        return session.query(cls).filter_by(user_id=user_id).all()

    @classmethod
    def get_by_credential_id(cls, session, credential_id):
        """
        Retrieves a WebAuthn credential by its unique credential ID.

        Parameters
        ----------
        session : AsyncSession
            The SQLAlchemy session used for querying the database.
        credential_id : str
            The unique identifier of the credential.

        Returns
        -------
        WebAuthnCredential | None
            The WebAuthnCredential object if found, otherwise `None`.
        """
        return session.query(cls).filter_by(credential_id=credential_id).first()

    @classmethod
    def delete_by_credential_id(cls, session, credential_id):
        """
        Deletes a WebAuthn credential by its unique credential ID.

        Parameters
        ----------
        session : AsyncSession
            The SQLAlchemy session used for querying the database.
        credential_id : str
            The unique identifier of the credential to delete.

        Returns
        -------
        bool
            True if the credential was deleted, False otherwise.
        """
        credential = cls.get_by_credential_id(session, credential_id)
        if credential:
            session.delete(credential)
            session.commit()
            return True
        return False
