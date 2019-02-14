package com.github.mjaulin.cognito.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
public class JwtTokenProvider implements AuthenticationProvider {

    @Value("${authentification.jwt.public.key.url}")
    private String authJwtPublicKeyUrl;

    @Value("${authentification.jwt.public.key.heaeder.id}")
    private String authJwtPublicKeyHeaderId;

    @Value("${authentification.jwt.key.user.id}")
    private String authJwtKeyUserId;

    @Value("${authentification.jwt.header}")
    private String authHeader;

    private Map<String, String> cachePublicKey = new CachePublicKey();

    public Authentication authenticate(HttpServletRequest req) {
        String token = req.getHeader(authHeader);
        log.trace("JWT Token : {}", token);
        return Optional.ofNullable(token)
                .filter(StringUtils::isNotBlank)
                .map(this::getKeyId)
                .map(this::getPublicKey)
                .map(pk -> this.getUserIdFromToken(pk, token))
                .map(userId -> new UsernamePasswordAuthenticationToken(userId, null, Collections.emptyList()))
                .orElse(null);
    }

    private String getKeyId(String token) {
        String header = new String(Base64.getDecoder().decode(token.split("\\.")[0]), StandardCharsets.UTF_8);
        ObjectMapper mapper = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        try {
            Map<String, String> json = mapper.readValue(header, new TypeReference<Map<String, String>>(){});
            if (json.containsKey(authJwtPublicKeyHeaderId)) {
                String kid = json.get(authJwtPublicKeyHeaderId);
                log.trace("Key Id from JWT header : {}", kid);
                return kid;
            } else {
                return null;
            }
        } catch (IOException e) {
            log.warn("Enable to parse header token", e);
        }
        return null;
    }

    private String getPublicKey(String kid) {
        if (cachePublicKey.containsKey(kid)) {
            return cachePublicKey.get(kid);
        }

        ResponseEntity<String> response = new RestTemplate().getForEntity(authJwtPublicKeyUrl + "/" + kid, String.class);
        if (!response.getStatusCode().is2xxSuccessful()) {
            log.warn("Error {} when getting public key : {}", response.getStatusCodeValue(), kid);
            return null;
        }

        String publicKey = response.getBody();
        log.trace("JWT Public Key :\n{}", publicKey);
        cachePublicKey.put(kid, publicKey);
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
        } catch (GeneralSecurityException e) {
            log.warn("Cannot generate ECPublicKey from :\n{}", publicKey);
        }
        return null;
    }

    private static byte[] parsePem(String publicKey) {
        publicKey = publicKey.replaceAll("-----BEGIN PUBLIC KEY-----\n", "");
        publicKey = publicKey.replaceAll("-----END PUBLIC KEY-----", "");
        publicKey = publicKey.replaceAll("\n", "");
        return Base64.getDecoder().decode(publicKey);
    }

    private class CachePublicKey extends LinkedHashMap<String, String> {

        private static final int LIMIT = 10;

        @Override
        public String put(String key, String value) {
            String result = super.putIfAbsent(key, value);
            if (super.size() > LIMIT){
                removeEldest();
            }
            return result;
        }

        private void removeEldest() {
            Iterator<String> iterator = this.keySet().iterator();
            if (iterator.hasNext()){
                this.remove(iterator.next());
            }
        }
    }
}
