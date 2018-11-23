package com.github.mjaulin.cognito.configuration;

import com.github.mjaulin.cognito.filter.AuthFilter;
import com.github.mjaulin.cognito.service.AuthService;
import com.github.mjaulin.cognito.service.JwtTokenProvider;
import com.github.mjaulin.cognito.service.MockProvider;
import com.github.mjaulin.cognito.service.UserIdProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class AuthConfig extends WebSecurityConfigurerAdapter {

    @Value("${authentification.active}")
    private Boolean authActive;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/ko", "/favicon.ico").permitAll()
                .anyRequest().authenticated()
                .and()
                .addFilterBefore(authFilter(), BasicAuthenticationFilter.class)
                .exceptionHandling().authenticationEntryPoint((req, resp, e) ->  resp.sendError(HttpStatus.UNAUTHORIZED.value()))
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
    }

    @Bean
    public AuthFilter authFilter() {
        return new AuthFilter(userIdProvider(), authService(), (req, resp, e) -> resp.sendRedirect(req.getContextPath() + "/ko"));
    }

    @Bean
    public UserIdProvider userIdProvider() {
        return authActive ? new JwtTokenProvider() : new MockProvider();
    }

    @Bean
    public AuthService authService() {
        return new AuthService();
    }
}
