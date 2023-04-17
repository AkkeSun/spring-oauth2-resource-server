package com.example.springoauth2resourceserver.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

    @GetMapping("/api/test")
    public Authentication apiTest(Authentication authentication) {
        return authentication;
    }
}