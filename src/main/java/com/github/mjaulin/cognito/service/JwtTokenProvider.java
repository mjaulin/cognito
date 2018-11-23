package com.github.mjaulin.cognito.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class JwtTokenProvider implements UserIdProvider {

    @Value("${authentification.jwt.public.key.url}")
    private String authJwtPublicKeyUrl;

    @Value("${authentification.jwt.public.key.heaeder.id}")
    private String authJwtPublicKeyHeaderId;

    @Value("${authentification.jwt.key.user.id}")
    private String authJwtKeyUserId;

    @Value("${authentification.jwt.header}")
    private String authHeader;

    public Optional<String> getUserId(HttpServletRequest req) {
        return Optional.ofNullable(req.getHeader(authHeader))
                .flatMap(token -> getKeyId(token)
                        .map(this::getPublicKey)
                        .map(pk -> this.getUserIdFromToken(pk, token))
                );
    }

    private Optional<String> getKeyId(String token) {
        String header = new String(Base64.getDecoder().decode(token.split("\\.")[0]), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            Map<String, String> json = mapper.readValue(header, new TypeReference<Map<String, String>>(){});
            String kid = json.get(authJwtPublicKeyHeaderId);
            log.debug("Key Id from JWT header : {}", kid);
            return Optional.ofNullable(kid);
        } catch (IOException e) {
            log.error("Enable to parse header token", e);
        }
        return Optional.empty();
    }

    private String getPublicKey(String kid) {
        ResponseEntity<String> response = new RestTemplate().getForEntity(authJwtPublicKeyUrl + "/" + kid, String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            log.error("Error {} when getting public key : {}", response.getStatusCodeValue(), kid);
            return null;
        }
        String publicKey = response.getBody();
        log.debug("JWT Public Key :\n{}", publicKey);
        return publicKey;
    }

    private String getUserIdFromToken(String publicKey, String token) {
        ECPublicKey key = parsePublicKey(publicKey);
        DecodedJWT jwt = JWT.require(Algorithm.ECDSA256(key, null))
                .build()
                .verify(token);
        return jwt.getClaim(authJwtKeyUserId).asString();
    }

    private ECPublicKey parsePublicKey(String publicKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(parsePem(publicKey));
            return (ECPublicKey) kf.generatePublic(keySpec);
        } catch (GeneralSecurityException | IOException e) {
            log.error("Cannot generate ECPublicKey from :\n {}", publicKey);
        }
        return null;
    }

    private byte[] parsePem(String publicKey) throws IOException {
        try (PemReader reader = new PemReader(new StringReader(publicKey))) {
            return reader.readPemObject().getContent();
        }
    }
}
