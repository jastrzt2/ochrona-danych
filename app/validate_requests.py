import math
import string

import string
password_allowed_characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
def is_password_valid(password):
    if len(password) < 8:
        return False
    
    if not any(c in string.ascii_lowercase for c in password):
        return False
    
    if not any(c in string.ascii_uppercase for c in password):
        return False
    
    if not any(c in string.digits for c in password):
        return False
    
    if not any(c in string.punctuation for c in password):
        return False
    
    return True

def validate_password_entropy(password):
    pool_size = 0

    if any(c in string.ascii_lowercase for c in password):
        pool_size += len(string.ascii_lowercase)
    if any(c in string.ascii_uppercase for c in password):
        pool_size += len(string.ascii_uppercase)
    if any(c in string.digits for c in password):
        pool_size += len(string.digits)
    if any(c in string.punctuation for c in password):
        pool_size += len(string.punctuation) 

    if pool_size == 0:
        return "Password is too weak."

    entropy = math.log2(pool_size) * len(password)

    MIN_ENTROPY = 60

    if entropy < MIN_ENTROPY:
        return "Password is too weak."
    return None

def validate_register_inputs(username, password, repeated_password, email):
    errors = []

    if len(username) > 100:
        errors.append("Username cannot exceed 100 characters.")
    if not username.isalnum():
        errors.append("Username can only contain letters and digits.")
        
    if not email:
        errors.append("Email is required.")
    if len(email) > 254:
        errors.append("Email cannot exceed 254 characters.")
    if '@' not in email or '.' not in email:
        errors.append("Invalid email format.")
    if any(c for c in email if c not in string.ascii_letters + string.digits + "@._-"):
        errors.append("Email contains invalid characters.")
    
    if password != repeated_password:
        errors.append("Passwords do not match.")
    if not is_password_valid(password):
        errors.append("Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.")
    entropy_error = validate_password_entropy(password)
    if entropy_error:
        errors.append(entropy_error)
    return "\n".join(errors) if errors else None

def validate_login_inputs(username, password, token):
    errors = []

    if len(username) > 100:
        errors.append("Username cannot exceed 100 characters.")
        
    if not token.isdigit():
        errors.append("TOTP token must contain only digits.")
    if len(token) != 6:
        errors.append("TOTP token must be exactly 6 digits.")

    return "\n".join(errors) if errors else None

def validate_note_create_or_edit(title, content, password):
    errors = []
        
    if not title.isalnum():
        errors.append("Title can only contain letters and digits.")    
    if len(title) == 0:
        errors.append("Title cannot be empty.")
    if len(title) > 50:
        errors.append("Title cannot exceed 50 characters.")
    
    if len(content) == 0:
        errors.append("Content cannot be empty.")
    if len(content) > 1000000:
        errors.append("Content cannot exceed 10000 characters.")

    return "\n".join(errors) if errors else None

def validate_change_password(current_password, new_password, confirm_password):
    errors = []

    if not current_password:
        errors.append("Current password is required.")
    if not new_password or not confirm_password:
        errors.append("New password and confirmation are required.")
    if new_password != confirm_password:
        errors.append("New password and confirmation must match.")
    if not is_password_valid(new_password):
        errors.append("Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.")
    if new_password:
        entropy_error = validate_password_entropy(new_password)
        if entropy_error:
            errors.append(entropy_error)
    return "\n".join(errors) if errors else None

def validate_reset_password(new_password, confirm_password):
    errors = []

    if not new_password or not confirm_password:
        errors.append("New password and confirmation are required.")
    if new_password != confirm_password:
        errors.append("New password and confirmation must match.")
    if not is_password_valid(new_password):
        errors.append("Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character.")
    if new_password:
        entropy_error = validate_password_entropy(new_password)
        if entropy_error:
            errors.append(entropy_error)
    return "\n".join(errors) if errors else None

def validate_forgot_password(email):
    errors = []

    if not email:
        errors.append("Email is required.")
    if len(email) > 254:
        errors.append("Email cannot exceed 254 characters.")
    if '@' not in email or '.' not in email:
        errors.append("Invalid email format.")
    if any(c for c in email if c not in string.ascii_letters + string.digits + "@._-"):
        errors.append("Email contains invalid characters.")

    return "\n".join(errors) if errors else None