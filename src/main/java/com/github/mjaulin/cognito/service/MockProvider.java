package com.github.mjaulin.cognito.service;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Slf4j
public class MockProvider implements UserIdProvider {

    @Value("${authentification.mock.identifiant}")
    private String mockIdentifiant;

    @Override
    public Optional<String> getUserId(HttpServletRequest req) {
        String userId = req.getParameter("user");
        if (StringUtils.isBlank(userId)) {
            userId = mockIdentifiant;
        }
        log.debug("User id {}", userId);
        return Optional.of(userId);
    }

}
