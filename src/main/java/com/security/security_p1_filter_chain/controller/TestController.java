package com.security.security_p1_filter_chain.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestController {

    @GetMapping("/public")
    public Map<String, String> publicEndpoint() {
        return Map.of("message", "Public endpoint accessible to all");
    }

    @GetMapping("/user")
    public Map<String, Object> userEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return Map.of(
                "message", "User endpoint accessed",
                "principal", auth.getName(),
                "authorities", auth.getAuthorities()
        );
    }

    @GetMapping("/admin")
    public Map<String, Object> adminEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return Map.of(
                "message", "Admin endpoint accessed",
                "principal", auth.getName(),
                "authorities", auth.getAuthorities()
        );
    }
}