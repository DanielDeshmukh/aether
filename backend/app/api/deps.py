import os
from jose import jwt
from cryptography.hazmat.primitives import serialization

# In a real security-first app, you'd fetch this from: 
# https://soxlevlubujfkshzbuov.supabase.co/auth/v1/keys
# But for now, we will use the Public Key string from your dashboard.

def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> str:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Security Validation Failed: Signature Mismatch",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # 1. Supabase ES256 Public Key 
        # (Replace this with the actual Public Key content if you have it, 
        # otherwise, we must use the JWKS endpoint to be 100% 'Secure by Design')
        
        # Proper way: Validate against Supabase's JWKS
        payload = jwt.decode(
            token, 
            JWT_SECRET, # This must be the PUBLIC KEY for ES256
            algorithms=["ES256"],
            audience="authenticated",
            options={"verify_signature": True} 
        )
        
        user_id: str = payload.get("sub")
        return user_id
    except Exception as e:
        print(f"Audit Log - Auth Failure: {str(e)}")
        raise credentials_exception