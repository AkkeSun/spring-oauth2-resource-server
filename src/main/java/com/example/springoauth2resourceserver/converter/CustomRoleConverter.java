package com.example.springoauth2resourceserver.converter;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/*
    scope 가 아닌 realm_access.roles 정보로 권한 제어를 하기 위한 컨버터
 */
public class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final String PRIFIX = "ROLE_";

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, Object> reams_access = jwt.getClaimAsMap("realm_access");
        if (reams_access == null) {
            return Collections.EMPTY_LIST;
        }
        Collection<GrantedAuthority> authorities =
            ((List<String>) (reams_access.get("roles"))).stream()
                .map(role -> PRIFIX + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return authorities;
    }
}
