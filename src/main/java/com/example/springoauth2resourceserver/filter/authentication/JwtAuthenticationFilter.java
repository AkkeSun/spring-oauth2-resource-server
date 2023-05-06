package com.example.springoauth2resourceserver.filter.authentication;

import com.example.springoauth2resourceserver.dto.LoginDTO;
import com.example.springoauth2resourceserver.signer.SecuritySigner;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
    인가서버를 대신하여 토큰을 발행하는 커스텀 필터
    1. 입력 파라미터 → LoginDTO 변경
    2. LoginDTO → UsernamePasswordAuthenticationToken 생성
    3. JWT 토큰 발행
 */
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // 토큰 발행기
    private final SecuritySigner securitySigner;

    // 알고리즘과 키를 가지고 있는 객채
    private final JWK jwk;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException {
        LoginDTO loginDTO = getLoginDTO(request);
        UsernamePasswordAuthenticationToken userToken = getUserToken(loginDTO);
        return getAuthenticationManager().authenticate(userToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain, Authentication authResult) {
        // JWT 토큰 발행
        User user = (User) authResult.getPrincipal();
        String jwtToken = securitySigner.getJwtToken(user, jwk);
        response.addHeader("Authorization", "Bearer " + jwtToken);
    }

    private LoginDTO getLoginDTO(HttpServletRequest request) {
        ObjectMapper om = new ObjectMapper();
        LoginDTO loginDTO = null;
        try {
            loginDTO = om.readValue(request.getInputStream(), LoginDTO.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return loginDTO;
    }

    private UsernamePasswordAuthenticationToken getUserToken(LoginDTO loginDTO) {
        return new UsernamePasswordAuthenticationToken(
            loginDTO.getUsername(), loginDTO.getPassword());
    }
}
