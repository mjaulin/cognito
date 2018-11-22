package com.github.mjaulin.cognito.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class JwtTokenProvider implements UserIdProvider {

    @Value("${authentification.jwt.public.key.url}")
    private String authJwtPublicKeyUrl;

    @Value("${authentification.jwt.key.user.id}")
    private String authJwtKeyUserId;

    @Value("${authentification.jwt.header}")
    private String authHeader;

    public Optional<String> getUserId(HttpServletRequest req) {
        return Optional.ofNullable(req.getHeader(authHeader))
                .flatMap(token -> getKeyId(token)
                        .map(this::getPublicKey)
                        .map(pk -> this.parseToken(pk, token))
                )
                .map(claims -> (String) claims.get(authJwtKeyUserId));
    }

    private Optional<String> getKeyId(String token) {
        String header = new String(Base64.getDecoder().decode(token.split("\\.")[0]), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            Map<String, String> json = mapper.readValue(header, new TypeReference<Map<String, String>>(){});
            return Optional.ofNullable(json.get("kid"));
        } catch (IOException e) {
            log.error("Enable to parse header token from header", e);
        }
        return Optional.empty();
    }

    private String getPublicKey(String kid) {
        String publicKey = new RestTemplate().getForObject(authJwtPublicKeyUrl + "/" + kid, String.class);
        log.debug("The Public Key is {}", publicKey);
        return publicKey;
    }

    private Claims parseToken(String publicKey, String payload) {
        return Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(payload)
                .getBody();
    }
}
