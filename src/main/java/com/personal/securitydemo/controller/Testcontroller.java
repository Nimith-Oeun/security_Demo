package com.personal.securitydemo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class Testcontroller {

    @GetMapping("")
    ResponseEntity<String> test(){
        return ResponseEntity.ok("Test successful");
    }

    @GetMapping("/admin")
    ResponseEntity<String> testAdmin(){
        return ResponseEntity.ok("Admin access granted");
    }
}
