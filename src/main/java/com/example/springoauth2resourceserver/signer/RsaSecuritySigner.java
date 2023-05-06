package com.example.springoauth2resourceserver.signer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.security.core.userdetails.UserDetails;

public class RsaSecuritySigner extends SecuritySigner {

    @Override
    public String getJwtToken(UserDetails user, JWK jwk) {
        RSASSASigner jwsSigner = null;
        try {
            jwsSigner =  new RSASSASigner(((RSAKey)jwk).toRSAPrivateKey());
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return super.getJwtTokenInternal(jwsSigner,user,jwk);
    }
}
