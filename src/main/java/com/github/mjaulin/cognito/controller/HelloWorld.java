package com.github.mjaulin.cognito.controller;

import com.github.mjaulin.cognito.model.User;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.stream.Collectors;

@RestController
@RequestMapping("/")
public class HelloWorld {

    @GetMapping
    public ResponseEntity hello() {
        return ResponseEntity.ok("Hello " + ((User) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername() + " !!!");
    }

    @GetMapping(value = "/request")
    public ResponseEntity request(@RequestHeader HttpHeaders headers) {
        return ResponseEntity.ok("<ul>" +
                String.join("", headers.entrySet().stream().map(entry -> "<li>" + entry.getKey() + " : " + String.join(", ",entry.getValue()) + "</li>").collect(Collectors.toList())) +
                "</ul>");
    }

    @GetMapping(value = "/ko")
    public ResponseEntity error() {
        return ResponseEntity.ok("Not authorized");
    }
}
