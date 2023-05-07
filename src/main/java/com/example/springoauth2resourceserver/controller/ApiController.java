package com.example.springoauth2resourceserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/api/user")
    // authentication : 스프링 시큐리티 인증 객채
    // Jwt : 검증에 성공한 JwtToken 의 principal 속성 정보. authentication 에서 꺼낼수도 있다
    public Authentication user(Authentication authentication,
        @AuthenticationPrincipal Jwt principal) {
        JwtAuthenticationToken authenticationToken = (JwtAuthenticationToken) authentication;
        String sub = (String) authenticationToken.getTokenAttributes().get("sub");
        String email = (String) authenticationToken.getTokenAttributes().get("email");
        String scope = (String) authenticationToken.getTokenAttributes().get("scope");
        Jwt tokenFromAuthentication = authenticationToken.getToken();

        String sub1 = principal.getClaim("sub");
        String email1 = principal.getClaim("email");
        String scope1 = principal.getClaim("scope");
        String token = principal.getTokenValue();
        return authentication;
    }
}
