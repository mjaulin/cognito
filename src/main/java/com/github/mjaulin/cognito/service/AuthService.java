package com.github.mjaulin.cognito.service;

import com.github.mjaulin.cognito.model.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Arrays;
import java.util.List;

public class AuthService {

    private static List<User> users = Arrays.asList(new User("n.jaulin"), new User("m.jaulin"));

     public User getUser(String username) {
        return users.stream()
                .filter(u -> username.equalsIgnoreCase(u.getUsername()))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("You're not authorized to access to the application"));
    }
}
