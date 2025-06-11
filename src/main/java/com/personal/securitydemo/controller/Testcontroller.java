package com.personal.securitydemo.controller;

import com.personal.securitydemo.dto.RegisterRequest;
import com.personal.securitydemo.security.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/test")
@RequiredArgsConstructor
public class Testcontroller {

    private final UserService userService;

    @GetMapping("")
    @PreAuthorize("hasAuthority('user:read')")
    ResponseEntity<String> test(){
        return ResponseEntity.ok("Test successful");
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('admin:write')")
    ResponseEntity<String> testAdmin(){
        return ResponseEntity.ok("Admin access granted");
    }

    @PostMapping("/register")
    public ResponseEntity<?>crateUser(@RequestBody RegisterRequest registerRequest){
        userService.createUser(registerRequest);
        return ResponseEntity.ok("User created: " + registerRequest.getUsername());
    }
}
