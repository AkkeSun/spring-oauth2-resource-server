package com.example.springoauth2resourceserver.config;

import com.example.springoauth2resourceserver.signer.MacSecuritySigner;
import com.example.springoauth2resourceserver.signer.RsaSecuritySigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SignatureConfig {

    private final String KEY_ID = "myKey";

    // MAC 기반 토큰 발행기
    @Bean
    public MacSecuritySigner macSecuritySigner() {
        return new MacSecuritySigner();
    }

    // MAC 기반 JWK
    @Bean
    public OctetSequenceKey octetSequenceKey() throws JOSEException {
        return new OctetSequenceKeyGenerator(256)
            .keyID(KEY_ID)
            .algorithm(JWSAlgorithm.HS256)
            .generate();
    }

    // RSA 기반 토큰 발행 객채
    @Bean
    public RsaSecuritySigner rsaSecuritySigner(){
        return new RsaSecuritySigner();
    }

    // RSA 기반 JWK
    @Bean
    public RSAKey rsaKey() throws JOSEException {
        RSAKey rsaKey = new RSAKeyGenerator(2048)
            .keyID(KEY_ID)
            .algorithm(JWSAlgorithm.RS256)
            .generate();
        return rsaKey;
    }
}
