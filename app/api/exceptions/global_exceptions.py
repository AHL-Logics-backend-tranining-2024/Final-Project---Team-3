from fastapi import HTTPException, status
from uuid import UUID


class EmailAlreadyExistsException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered",
        )


class InvalidPasswordException(HTTPException):
    def __init__(self, errors: list):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"password_errors": errors},
        )


class PriceValidationException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Price must be a positive number.",
        )


class StockValidationException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Stock must be greater than zero.",
        )


class UserNotFoundException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )


class ProductAlreadyExistsException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail="Product already exists.",
        )


class ProductNotFoundException(Exception):
    def __init__(self, product_id: UUID):
        self.message = f"Product not found with ID = {product_id}"
        super().__init__(self.message)


class InvalidProductDataException(HTTPException):
    def __init__(self, errors: list):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"product_errors": errors},
        )


class InvalidUUIDException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The provided user ID is not a valid UUID.",
        )


class ProductValidationException(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The provided product is not validated ! .",
        )


class MissingFieldException(Exception):
    def __init__(self, message):
        self.message = message
