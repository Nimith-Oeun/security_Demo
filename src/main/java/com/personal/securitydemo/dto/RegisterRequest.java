package com.personal.securitydemo.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.personal.securitydemo.enumeration.Role;
import lombok.Data;

import java.util.Set;

@Data
public class RegisterRequest {

    @JsonProperty("user_name")
    private String username;


    private String password;

    @JsonProperty("first_name")
    private String firstName;

    @JsonProperty("last_name")
    private String lastName;

    @JsonProperty("confirm_password")
    private String confirmPassword;

    private String roles;
}
