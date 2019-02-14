package com.github.mjaulin.cognito.service;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

public interface AuthenticationProvider {

    Authentication authenticate(HttpServletRequest req);
}
