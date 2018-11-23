package com.github.mjaulin.cognito.filter;

import com.github.mjaulin.cognito.service.AuthService;
import com.github.mjaulin.cognito.service.UserIdProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

public class AuthFilter extends OncePerRequestFilter {

    private final UserIdProvider userIdProvider;
    private final AuthService authService;
    private final AuthenticationFailureHandler failureHandler;

    public AuthFilter(UserIdProvider userIdProvider, AuthService authService, AuthenticationFailureHandler failureHandler) {
        this.userIdProvider = userIdProvider;
        this.authService = authService;
        this.failureHandler = failureHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) throws ServletException, IOException {
        try {
            Authentication auth = userIdProvider.getUserId(req)
                    .filter(this::authenticationIsRequired)
                    .map(authService::getUser)
                    .map(user -> (Authentication) new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList()))
                    .orElse(new UsernamePasswordAuthenticationToken(null, null));
            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(req, resp);
        } catch (AuthenticationException e) {
            logger.warn("Authentication failed");
            SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(null, null));
            failureHandler.onAuthenticationFailure(req, resp, e);
        }
    }

    private boolean authenticationIsRequired(String username) {
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        return existingAuth == null || !existingAuth.isAuthenticated() || !existingAuth.getName().equals(username);
    }
}
