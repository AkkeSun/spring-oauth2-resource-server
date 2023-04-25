package com.example.springoauth2resourceserver.signer;

import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import org.springframework.security.core.userdetails.UserDetails;

public class MacSecuritySigner extends SecuritySigner {

    @Override
    public String getJwtToken(UserDetails user, JWK jwk) {
        MACSigner jwsSigner = null;
        try {
            jwsSigner = new MACSigner(((OctetSequenceKey) jwk).toSecretKey());
        } catch (KeyLengthException e) {
            throw new RuntimeException(e);
        }
        return super.getJwtTokenInternal(jwsSigner, user, jwk);
    }
}
