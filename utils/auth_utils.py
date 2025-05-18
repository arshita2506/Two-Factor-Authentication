import bcrypt

def hash_password(password):
    """
    Hash the user's password using bcrypt
    """
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def check_password(password, hashed_password):
    """
    Verify a password against the stored hash
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
