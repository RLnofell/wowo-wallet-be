package com.wowo.wowo.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.wowo.wowo.model.User;
import com.wowo.wowo.util.ObjectUtil;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
@ConfigurationProperties(prefix = "jwt")
public class JwtService {

    private static final int expire = 60 * 24;
    private static String secret;
    private static Algorithm algorithm;
    private static JWTVerifier verifier;

    public void setSecret(String secret) {
        JwtService.secret = secret;
        JwtService.algorithm = Algorithm.HMAC256(secret);
        JwtService.verifier = JWT.require(JwtService.algorithm).build();
    }

    public static String generateToken(User user) {
        java.util.Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("userId", user.getId());
        claims.put("id", user.getId());
        claims.put("email", user.getEmail());
        claims.put("username", user.getUsername());
        if (user.getRole() != null) {
            claims.put("role", java.util.Map.of("name", user.getRole().getName()));
        } else {
            claims.put("role", java.util.Map.of("name", "User"));
        }
        return JWT.create()
                .withSubject(String.valueOf(user.getId()))
                .withPayload(ObjectUtil.parseJson(claims))
                .withExpiresAt(Date.from(Instant.now()
                        .plus(expire, ChronoUnit.MINUTES)))
                .sign(algorithm);

    }

    public static String generateToken(String subject, String payload, int expire) {
        return JWT.create()
                .withSubject(subject)
                .withPayload(payload)
                .withExpiresAt(Date.from(Instant.now()
                        .plus(expire, ChronoUnit.MINUTES)))
                .sign(algorithm);

    }

    /**
     * Tạo token với người dùng được truyền vào và hết hạn sau {@code expire} phút
     *
     * @param user   người dùng
     * @param expire thời gian hết hạn token
     *
     * @return chuỗi token
     */
    public static String generateToken(User user, int expire) {
        java.util.Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("userId", user.getId());
        claims.put("id", user.getId());
        claims.put("email", user.getEmail());
        claims.put("username", user.getUsername());
        if (user.getRole() != null) {
            claims.put("role", java.util.Map.of("name", user.getRole().getName()));
        } else {
            claims.put("role", java.util.Map.of("name", "User"));
        }
        return JWT.create()
                .withSubject(String.valueOf(user.getId()))
                .withPayload(ObjectUtil.parseJson(claims))
                .withExpiresAt(Date.from(Instant.now()
                        .plus(expire, ChronoUnit.MINUTES)))
                .sign(algorithm);

    }

    public static DecodedJWT verifyToken(String token) {
        try {
            return verifier.verify(token);
        } catch (Exception e) {
            return null;
        }
    }
}
