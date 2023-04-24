package com.example.springoauth2resourceserver.filter;

import com.example.springoauth2resourceserver.dto.LoginDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/*
    인가서버를 대신하여 토큰을 발행하는 커스텀 필터
    1. 입력 파라미터 → LoginDTO 변경
    2. LoginDTO → UsernamePasswordAuthenticationToken 생성
    3. UsernamePasswordAuthenticationToken 시큐리티에 저장
 */
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException {
        LoginDTO loginDTO = getLoginDTO(request);
        UsernamePasswordAuthenticationToken userToken = getUserToken(loginDTO);
        return getAuthenticationManager().authenticate(userToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain, Authentication authResult)
        throws IOException, ServletException {

        // 인증 객채 security 에 저장
        SecurityContextHolder.getContext().setAuthentication(authResult);
        getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
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
