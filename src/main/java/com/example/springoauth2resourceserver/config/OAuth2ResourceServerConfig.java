package com.example.springoauth2resourceserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig {

    private final OAuth2ResourceServerProperties properties;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(request -> request.anyRequest().authenticated());
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }

    /*
    // spring.security.oauth2.resourceserver.jwt.issuer-uri 를 통한 생성 (해당 설정 필요)
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation(properties.getJwt().getIssuerUri());
    }


    @Bean
    public JwtDecoder jwtDecoder2() {
        return JwtDecoders.fromOidcIssuerLocation(properties.getJwt().getIssuerUri());
    }
     */

    // spring.security.oauth2.resourceserver.jwt.jwk-set-uri 를 통한 생성 (해당 설정 필요)
    // 이 경우 비대칭 키의 알고리즘을 변경할 수 있다. (인가서버에서도 알고리즘을 변경해주어야한다)
    @Bean
    public JwtDecoder jwtDecoder3() {
        return NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri())
            .jwsAlgorithm(SignatureAlgorithm.RS512)
            .build();
    }

}
