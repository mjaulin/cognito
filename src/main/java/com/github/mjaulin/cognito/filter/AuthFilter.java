package com.github.mjaulin.cognito.filter;

import com.github.mjaulin.cognito.service.AuthService;
import com.github.mjaulin.cognito.service.UserIdProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
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

    public AuthFilter(UserIdProvider userIdProvider, AuthService authService) {
        this.userIdProvider = userIdProvider;
        this.authService = authService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) throws ServletException, IOException {
        userIdProvider.getUserId(req)
                .map(authService::getUser)
                .map(user -> new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList()))
                .ifPresent(auth -> SecurityContextHolder.getContext().setAuthentication(auth));
        chain.doFilter(req, resp);
    }
}
