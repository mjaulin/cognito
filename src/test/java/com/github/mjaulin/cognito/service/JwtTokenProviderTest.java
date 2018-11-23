package com.github.mjaulin.cognito.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.BlockJUnit4ClassRunner;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@RunWith(BlockJUnit4ClassRunner.class)
public class JwtTokenProviderTest {

    @Test
    public void testParseToken() {
        // given
        String token = "eyJ0eXAiOiJKV1QiLCJraWQiOiIyMGNlYTJkYi0zMzcwLTRlMjctOWU3NS1jZmJlMmY3NDNiZmMiLCJhbGciOiJFUzI1NiIsImlzcyI6Imh0dHBzOi8vY29nbml0by1pZHAuZXUtd2VzdC0xLmFtYXpvbmF3cy5jb20vZXUtd2VzdC0xX0hoaTRDcXllMSIsImNsaWVudCI6IjJoNWIxNTdwcDRhcnJrY2picnA3czRpNmRlIiwic2lnbmVyIjoiYXJuOmF3czplbGFzdGljbG9hZGJhbGFuY2luZzpldS13ZXN0LTE6NDkyMTE0MzgxMjU3OmxvYWRiYWxhbmNlci9hcHAvZWxiLWRldi1udGkvZmRjMzlkMWQwZmVmZWM4YyIsImV4cCI6MTU0MjkxODQ4MH0=.eyJzdWIiOiIxZmJlODUzNS0xYTgzLTRlNjEtOGFhMi02NjM1NjQ0ZTNlOTAiLCJlbWFpbF92ZXJpZmllZCI6InRydWUiLCJlbWFpbCI6Im0uamF1bGluQGdyb3VwZW9uZXBvaW50LmNvbSIsInVzZXJuYW1lIjoibS5qYXVsaW4ifQ==.MyQV9RRgeLSxCzgXu0SfgIWO-9CRkR4gx2tBOuU9Z-lmK1WLkpIn7bPiwnAXGzzi7b6rT-txbheqnIAeFpgTTg==";

        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETE6rrFql2vf/vjLui5L7yGxATbJL\n" +
                "rBmpluGWlZqv7kckZhpv34I/vCdF2aTerJqIDak0ErNkkawIN/auwRCZAA==\n" +
                "-----END PUBLIC KEY-----";

        // when
        ECPublicKey key = getPublicKey(publicKey);
        DecodedJWT jwt = JWT.require(Algorithm.ECDSA256(key, null))
                .build()
                .verify(token);

        // then
        assertNotNull(jwt);
        assertEquals(jwt.getClaim("username").asString(), "ZK1133");
    }

    private static ECPublicKey getPublicKey(String publicKey) {
        try {
            KeyFactory kf = KeyFactory.getInstance("EC");
            EncodedKeySpec keySpec = new X509EncodedKeySpec(parsePem(publicKey));
            return (ECPublicKey) kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Could not reconstruct the public key, the given algorithm could not be found.");
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            System.out.println("Could not reconstruct the public key");
        }
        return null;
    }

    private static byte[] parsePem(String publicKey) {
       publicKey = publicKey.replaceAll("-----BEGIN PUBLIC KEY-----\n", "");
       publicKey = publicKey.replaceAll("-----END PUBLIC KEY-----", "");
       publicKey = publicKey.replaceAll("\n", "");
       return Base64.getDecoder().decode(publicKey);
    }
}
