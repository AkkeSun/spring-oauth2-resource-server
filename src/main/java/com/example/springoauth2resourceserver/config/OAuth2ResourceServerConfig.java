package com.example.springoauth2resourceserver.config;

import com.example.springoauth2resourceserver.filter.authentication.JwtAuthenticationFilter;
import com.example.springoauth2resourceserver.filter.authorization.JwtAuthorizationMacFilter;
import com.example.springoauth2resourceserver.signer.MacSecuritySigner;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@RequiredArgsConstructor
public class OAuth2ResourceServerConfig {

    private final MacSecuritySigner macSecuritySigner;
    private final OctetSequenceKey octetSequenceKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.authorizeRequests((request) -> request.antMatchers("/").permitAll()
            .anyRequest().authenticated());
        http.userDetailsService(userDetailsService());
        http.addFilterBefore(jwtAuthenticationFilter(macSecuritySigner, octetSequenceKey),
            UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(new JwtAuthorizationMacFilter(octetSequenceKey),
            UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // 테스트를 위한 유저 객채 저장
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user =
            User.withUsername("user").password("1234").authorities("ROLE_USER").build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(MacSecuritySigner macSecuritySigner,
        OctetSequenceKey octetSequenceKey) throws Exception {
        JwtAuthenticationFilter filter =
            new JwtAuthenticationFilter(macSecuritySigner, octetSequenceKey);
        filter.setAuthenticationManager(authenticationManager(null));
        return filter;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
        throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
