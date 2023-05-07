package com.example.springoauth2resourceserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ExceptionController {

    @GetMapping("/exception/denied")
    public String accessDeniedHandler() {
        return "접근 권한이 없습니다";
    }
}
