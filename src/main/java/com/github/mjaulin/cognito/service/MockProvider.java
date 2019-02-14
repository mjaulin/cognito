package com.github.mjaulin.cognito.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Optional;

@Slf4j
public class MockProvider implements AuthenticationProvider {

    @Value("${authentification.mock.identifiant:}")
    private String mockIdentifiant;

    @Override
    public Authentication authenticate(HttpServletRequest req) {
        String userId = req.getParameter("user");
        return StringUtils.isNotBlank(userId) ? createAuthentication(userId) :
                Optional.ofNullable(req.getSession(false))
                        .map(session -> session.getAttribute("auth"))
                        .map(o -> (Authentication) o)
                        .orElse(createAuthentication(mockIdentifiant));
    }

    private Authentication createAuthentication(String userId) {
        return new UsernamePasswordAuthenticationToken(userId, userId, Collections.emptyList());
    }

}

