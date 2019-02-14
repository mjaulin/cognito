package com.github.mjaulin.cognito.configuration;

import com.github.mjaulin.cognito.filter.AuthFilter;
import com.github.mjaulin.cognito.service.AuthService;
import com.github.mjaulin.cognito.service.AuthenticationProvider;
import com.github.mjaulin.cognito.service.JwtTokenProvider;
import com.github.mjaulin.cognito.service.MockProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

import java.util.Collections;

@Configuration
public class AuthConfig {

    @Value("${authentification.active}")
    private Boolean authActive;

    private static final String URL_AUTH_ERROR = "/ko";

    @Bean
    public AuthFilter authFilter(AuthenticationProvider authProvider, AuthService authService) {
        return new AuthFilter(authProvider, authService,
                (req, resp) -> resp.sendRedirect(req.getContextPath() + URL_AUTH_ERROR),
                (req, resp) -> resp.sendError(HttpStatus.UNAUTHORIZED.value()),
                Collections.singletonList("^" + URL_AUTH_ERROR + "(/|)$"),
                Collections.singletonList("^/healthcheck(/|)$")
        );
    }

    @Bean
    public AuthenticationProvider authProvider() {
        return authActive ? new JwtTokenProvider() : new MockProvider();
    }

    @Bean
    public AuthService authService() {
        return new AuthService();
    }

}
