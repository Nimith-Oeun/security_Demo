package com.personal.securitydemo.enumeration;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static com.personal.securitydemo.enumeration.RolePermission.*;

import java.util.Set;
import java.util.stream.Collectors;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Slf4j
public enum Role {

    ADMIN(Set.of(
            ADMIN_READ ,
            ADMIN_WRITE,
            USER_READ,
            USER_WRITE
    )) ,
    USER(Set.of(
            USER_READ,
            ADMIN_READ
    ));

    /**
     * A set of permissions associated with the role.
     */
    private final Set<RolePermission> permissions;


    /**
     * Returns a set of granted authorities based on the role's permissions.
     *
     * @return a set of SimpleGrantedAuthority objects representing the role's permissions
     */
    public Set<SimpleGrantedAuthority> getAuthorities() {

        Set<SimpleGrantedAuthority> grantedAuthorities = this.permissions.stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getDescription()))
                .collect(Collectors.toSet());

        log.info("Granted authorities {}", grantedAuthorities);

        // Add the role to the authorities

        SimpleGrantedAuthority role = new SimpleGrantedAuthority("ROLE_" + this.name());
        grantedAuthorities.add(role);

        log.info("Granted authorities for role {}: {}", this.name(), grantedAuthorities);

        return grantedAuthorities;
    }
}
