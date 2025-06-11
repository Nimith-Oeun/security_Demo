package com.personal.securitydemo.security;

import com.personal.securitydemo.dto.RegisterRequest;
import com.personal.securitydemo.model.User;

import java.util.Optional;

public interface UserService {
    Optional<AuthUser> findByUsername(String username);
    User createUser(RegisterRequest registerRequest);
}
