package com.personal.securitydemo.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@AllArgsConstructor
@Builder
public class LoginRespones {
    private String userName;
    private String firstName;
    private String lastName;
    private String token;
    private String[] authorities;
}