from fastapi import HTTPException, status
import re
from app.api.exceptions.global_exceptions import InvalidPasswordException


def validate_password(password: str):
    errors = []

    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("Password must contain at least one special character.")

    if errors:
        raise InvalidPasswordException(errors)


#
