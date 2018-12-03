package com.github.mjaulin.cognito.security;

import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;

public interface AuthenticationProvider {

    Authentication authenticate(HttpServletRequest req);
}
