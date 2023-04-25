package com.example.springoauth2resourceserver.filter.authorization;

import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.List;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

/*
    JwtAuthorizationMacFilter : JWT 토큰을 MAC 알고리즘에 의해 검증하며 검증 성공시 인증 및 인가를 처리하는 필터
    OncePerRequestFilter : 여러번 요청해도 한번만 실행하도록 하는 필터
    1. 헤더에서 JWT 토큰 추출
    2. JWT 토큰 인가 심사
    3. JWT 토큰에서 사용자 정보 추출
    4. 사용자 정보로 UserDetails 생성
    5. 인증 처리
 */
@RequiredArgsConstructor
public class JwtAuthorizationMacFilter extends OncePerRequestFilter {

    private final OctetSequenceKey jwk;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain chain) {
        try {
            String token = request.getHeader("Authorization");
            if (token == null || !token.startsWith("Bearer ")) {
                chain.doFilter(request, response);
                return;
            }
            System.out.println("TOKEN : " + token);
            // ----- 토큰 검증 -----
            SignedJWT signedJWT = SignedJWT.parse(token.replace("Bearer ", ""));
            if (signedJWT.verify(new MACVerifier(jwk.toSecretKey()))) {
                // 토큰에서 사용자 정보와 권한 추출
                JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
                String username = jwtClaimsSet.getClaim("username").toString();
                List<String> authority = (List) jwtClaimsSet.getClaim("authority");

                if (username != null) {
                    // 추출한 정보로 UserDetails 생성
                    UserDetails user = User.withUsername(username)
                        .password(UUID.randomUUID().toString())
                        .authorities(authority.get(0))
                        .build();

                    // ----- 인증 처리 -----
                    Authentication authentication =
                        new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            chain.doFilter(request, response);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
