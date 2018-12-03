package com.github.mjaulin.cognito.model;

import lombok.Getter;

@Getter
public class User {

    private String username;

    public User(String username) {
        this.username = username;
    }

}
