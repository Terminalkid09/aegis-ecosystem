import os
from fastapi import Header, HTTPException, status, Depends
from typing import Optional

def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """
    Verifica che la richiesta contenga l'header X-Api-Key corretto.
    La chiave è letta dalla variabile d'ambiente AEGIS_API_KEY.
    """
    expected_key = os.getenv("AEGIS_API_KEY")
    
    # Se la chiave non è configurata sul server, blocca per sicurezza
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API Key not configured on server"
        )
    
    if x_api_key != expected_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing X-Api-Key"
        )
    return x_api_key
