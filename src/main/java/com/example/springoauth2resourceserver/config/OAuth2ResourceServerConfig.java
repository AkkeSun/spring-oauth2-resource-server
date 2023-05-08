package com.example.springoauth2resourceserver.config;

import com.example.springoauth2resourceserver.converter.CustomRoleConverter;
import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
public class OAuth2ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests()
            .antMatchers("/photos/1").permitAll()
            .antMatchers("/photos/2").hasAuthority("ROLE_default-roles-oauth2")
            .anyRequest().authenticated();

        // 필터 적용
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new CustomRoleConverter());
        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(converter);

        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        http.exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest httpServletRequest,
                HttpServletResponse httpServletResponse, AccessDeniedException e)
                throws IOException {
                httpServletResponse.sendRedirect("/exception/denied");
            }
        });
        return http.build();
    }
}
