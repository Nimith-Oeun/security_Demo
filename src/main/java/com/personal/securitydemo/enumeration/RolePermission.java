package com.personal.securitydemo.enumeration;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public enum RolePermission {
    ADMIN_READ("admin:read"),
    ADMIN_WRITE("admin:write"),
    USER_READ("user:read"),
    USER_WRITE("user:write");

    private final String description;
}
