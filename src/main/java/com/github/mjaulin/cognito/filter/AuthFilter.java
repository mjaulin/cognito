package com.github.mjaulin.cognito.filter;

import com.github.mjaulin.cognito.model.User;
import com.github.mjaulin.cognito.service.AuthService;
import com.github.mjaulin.cognito.service.AuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
public class AuthFilter extends OncePerRequestFilter {

    private final AuthenticationProvider authProvider;
    private final AuthService authService;
    private final ErrorHandler failureHandler;
    private final ErrorHandler unauthorizedHandler;
    private final Collection<Pattern> permitAll;
    private final Collection<Pattern> ignore;

    public AuthFilter(AuthenticationProvider authProvider, AuthService authService,
               ErrorHandler failureHandler,
               ErrorHandler unauthorizedHandler,
               Collection<String> permitAll,
               Collection<String> ignore) {
        this.authProvider = authProvider;
        this.authService = authService;
        this.failureHandler = failureHandler;
        this.unauthorizedHandler = unauthorizedHandler;
        this.permitAll = permitAll.stream().map(Pattern::compile).collect(Collectors.toList());
        this.ignore = ignore.stream().map(Pattern::compile).collect(Collectors.toList());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) throws ServletException, IOException {

        if (isIgnoredPath(req)) {
            chain.doFilter(req, resp);
            return;
        }

        Authentication auth = authProvider.authenticate(req);

        if (auth == null) {
            log.warn("User id must be provided for path : {}", req.getServletPath());
            unauthorizedHandler.onError(req, resp);
            return;
        }

        if (authenticationIsRequired(req, auth)) {
            try {
                User user = authService.getUser(auth.getName());
                saveAuthentication(req, auth, user);
                log.debug("Authentication success for user : {}", auth.getName());
            } catch(AuthenticationException e){
                log.warn("Authentication failed : {}", e.getMessage());
                auth.setAuthenticated(false);
                saveAuthentication(req, auth, null);
                failureHandler.onError(req, resp);
                return;
            }
        }
        chain.doFilter(req, resp);
    }

    private boolean isIgnoredPath(HttpServletRequest req) {
        return ignore.stream().anyMatch(pattern -> pattern.matcher(req.getServletPath()).find());
    }

    private boolean pathUnsecured(HttpServletRequest req) {
        return permitAll.stream().anyMatch(pattern -> pattern.matcher(req.getServletPath()).find());
    }

    private boolean authenticationIsRequired(HttpServletRequest req, Authentication auth) {
        Authentication previousAuth = (Authentication) req.getSession().getAttribute("auth");
        return previousAuth == null || !previousAuth.getName().equals(auth.getName()) || (!auth.isAuthenticated() && !pathUnsecured(req));
    }

    private void saveAuthentication(HttpServletRequest req, Authentication auth, User user) {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(auth);
        if (req.isRequestedSessionIdValid()) {
            req.getSession().invalidate();
        }
        req.getSession().setAttribute("auth", auth);
        req.getSession().setAttribute("user", user);
    }

    public interface ErrorHandler {
        void onError(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException;
    }

}
