import pyotp

def generate_totp_secret():
    """
    Generate a new base32 secret key for a user
    """
    return pyotp.random_base32()

def verify_totp(secret, otp_input):
    """
    Verify the OTP entered by the user
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(otp_input)
