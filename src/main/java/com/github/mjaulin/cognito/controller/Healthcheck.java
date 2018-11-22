package com.github.mjaulin.cognito.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/healthcheck")
public class Healthcheck {

    @GetMapping
    public ResponseEntity healthcheck() {
        return ResponseEntity.noContent().build();
    }
}
