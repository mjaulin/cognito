package com.github.mjaulin.cognito.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class AuthConfig {

    @Value("${authentification.active}")
    private Boolean authActive;

    @Bean
    public AuthFilter authFilter(AuthenticationProvider authenticationProvider, AuthService authService) {
        return new AuthFilter(authenticationProvider, authService,
                (req, resp) -> resp.sendRedirect(req.getContextPath() + "/ko"),
                (req, resp) -> resp.sendError(HttpStatus.UNAUTHORIZED.value()),
                Arrays.asList("^/ko$", "^/request$", "^/css/.*", "^/js/.*"),
                Collections.singleton("^/healthcheck(/|)$")
        );
    }

    @Bean
    public AuthenticationProvider userIdProvider() {
        return authActive ? new JwtTokenProvider() : new MockProvider();
    }

    @Bean
    public AuthService authService() {
        return new AuthService();
    }
}
