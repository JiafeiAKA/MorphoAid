package com.example.MorphoAid.security.jwt;

import com.example.MorphoAid.security.services.UserDetailsImpl;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.Method;
import java.security.Key;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class JwtUtilsTest {

    private JwtUtils jwtUtils;
    private Authentication auth;
    private final String email = "admin@example.com";
    private final String jwtSecret = "ZmFrZVNlY3JldE1vcnBob0FpZEtleTIwMjU2ODc2NTQzMjE=";
    private final int jwtExpirationMs = 3600000;

    @BeforeEach
    void setUp() {
        jwtUtils = new JwtUtils();
        ReflectionTestUtils.setField(jwtUtils, "jwtSecret", jwtSecret);
        ReflectionTestUtils.setField(jwtUtils, "jwtExpirationMs", jwtExpirationMs);

        UserDetailsImpl userDetails = new UserDetailsImpl(
                1L,
                "admin",
                email,
                "encoded-password",
                "Admin",
                "User",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );
        auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    private Key getPrivateKeyViaReflection() {
        try {
            Method method = JwtUtils.class.getDeclaredMethod("key");
            method.setAccessible(true);
            return (Key) method.invoke(jwtUtils);
        } catch (Exception e) {
            throw new RuntimeException("Unable to access key() method", e);
        }
    }

    private String generateToken() {
        return jwtUtils.generateJwtToken(auth);
    }

    // === UTC-06 ===
    @Test
    void generateJwtToken_shouldReturnValidToken() {
        String token = generateToken();
        assertNotNull(token);
        assertFalse(token.isEmpty());
    }

    @Test
    void generateJwtToken_shouldContainCorrectSubject() {
        String token = generateToken();
        String subject = jwtUtils.getUserNameFromJwtToken(token);
        assertEquals(email, subject);
    }

    // === UTC-07 ===
    @Test
    void getUserNameFromJwtToken_shouldReturnEmailIfValid() {
        String token = generateToken();
        String extracted = jwtUtils.getUserNameFromJwtToken(token);
        assertEquals(email, extracted);
    }

    @Test
    void getUserNameFromJwtToken_shouldThrowIfTampered() {
        String tampered = "eyJhbGciOiJIUzI1NiJ9.invalid.payload.signature";
        assertThrows(Exception.class, () -> jwtUtils.getUserNameFromJwtToken(tampered));
    }

    // === UTC-08 ===
    @Test
    void validateJwtToken_shouldReturnTrueIfValid() {
        String token = generateToken();
        assertTrue(jwtUtils.validateJwtToken(token));
    }

    @Test
    void validateJwtToken_shouldReturnFalseIfExpired() {
        Key key = getPrivateKeyViaReflection();

        String expiredToken = io.jsonwebtoken.Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date(System.currentTimeMillis() - 7200000))
                .setExpiration(new Date(System.currentTimeMillis() - 3600000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        assertFalse(jwtUtils.validateJwtToken(expiredToken));
    }

    @Test
    void validateJwtToken_shouldReturnFalseIfMalformed() {
        assertFalse(jwtUtils.validateJwtToken("abc.def"));
    }

    @Test
    void validateJwtToken_shouldReturnFalseIfUnsupported() {
        assertFalse(jwtUtils.validateJwtToken("this-is-not-a-jwt-token"));
    }

    @Test
    void validateJwtToken_shouldReturnFalseIfEmpty() {
        assertFalse(jwtUtils.validateJwtToken(""));
    }
}
