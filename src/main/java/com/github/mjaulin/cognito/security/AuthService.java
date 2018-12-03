package com.github.mjaulin.cognito.security;

import com.github.mjaulin.cognito.model.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Slf4j
public class AuthService {

    private static List<User> users = Arrays.asList(new User("n.jaulin"), new User("m.jaulin"));

    public User getUser(String username) {
        log.debug("Get user {} in db", username);
        return users.stream()
                .filter(u -> username.equalsIgnoreCase(u.getUsername()))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("User " + username +" is not authorized to access to the application"));
    }
}
