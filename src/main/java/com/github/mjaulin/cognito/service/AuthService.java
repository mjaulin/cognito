package com.github.mjaulin.cognito.service;

import com.github.mjaulin.cognito.model.User;

public class AuthService {

    public User getUser(String s) {
        return new User(s);
    }
}
