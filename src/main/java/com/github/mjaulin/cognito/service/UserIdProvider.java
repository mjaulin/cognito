package com.github.mjaulin.cognito.service;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

public interface UserIdProvider {

    Optional<String> getUserId(HttpServletRequest req);
}
