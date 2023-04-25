package com.example.springoauth2resourceserver.signer;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.core.userdetails.UserDetails;

public abstract class SecuritySigner {

    public abstract String getJwtToken(UserDetails user, JWK jwk);

    protected String getJwtTokenInternal(MACSigner jwsSigner, UserDetails user, JWK jwk) {

        // header
        JWSHeader header = new JWSHeader.Builder((JWSAlgorithm) jwk.getAlgorithm())
            .keyID(jwk.getKeyID()).build();

        // payload
        List<String> authorities = user.getAuthorities().stream()
            .map(auth -> auth.getAuthority())
            .collect(Collectors.toList());
        JWTClaimsSet payload = new JWTClaimsSet.Builder()
            .subject("user")
            .issuer("http://localhost:8081") // 발행자 정보
            .claim("username", user.getUsername())
            .claim("authority", authorities)
            .expirationTime(new Date(new Date().getTime() + 60 * 1000 * 5)) // 5분
            .build();

        // signature
        SignedJWT signedJWT = new SignedJWT(header, payload);
        try {
            signedJWT.sign(jwsSigner);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
        return signedJWT.serialize();
    }

}
