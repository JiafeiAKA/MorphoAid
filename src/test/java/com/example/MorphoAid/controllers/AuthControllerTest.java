package com.example.MorphoAid.controllers;

import com.example.MorphoAid.DTO.request.LoginRequest;
import com.example.MorphoAid.DTO.request.SignupRequest;
import com.example.MorphoAid.DTO.response.JwtResponse;
import com.example.MorphoAid.models.ERole;
import com.example.MorphoAid.models.Role;
import com.example.MorphoAid.security.jwt.JwtUtils;
import com.example.MorphoAid.security.services.UserDetailsImpl;
import com.example.MorphoAid.repository.RoleRepository;
import com.example.MorphoAid.repository.UserRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
public class AuthControllerTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private JwtUtils jwtUtils;
    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks private AuthController authController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(passwordEncoder.encode(any())).thenReturn("encoded-password");
        when(userRepository.save(any())).thenAnswer(i -> i.getArgument(0));
    }

    private SignupRequest validSignup(String role) {
        SignupRequest s = new SignupRequest();
        s.setUsername("testuser");
        s.setEmail("test@example.com");
        s.setPassword("password123");
        s.setConfirmPassword("password123");
        s.setFirstName("Test");
        s.setLastName("User");
        s.setAgree(true);
        s.setRoles(role);
        return s;
    }

    private LoginRequest login(String email, String password) {
        LoginRequest login = new LoginRequest();
        login.setEmail(email);
        login.setPassword(password);
        return login;
    }

    // === UTC-01 ===

    @Test
    void testAuthenticate_CorrectCredentials() {
        LoginRequest req = login("admin@example.com", "Admin123");

        Authentication auth = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(auth);

        UserDetailsImpl details = new UserDetailsImpl(
                1L,
                "adminuser",
                "admin@example.com",
                "Admin",
                "User",
                "encoded-password",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        when(auth.getPrincipal()).thenReturn(details);
        when(jwtUtils.generateJwtToken(any())).thenReturn("token");

        ResponseEntity<?> res = authController.authenticateUser(req);
        assertEquals(200, res.getStatusCodeValue());
        assertTrue(res.getBody() instanceof JwtResponse);
    }

    @Test
    void testAuthenticate_InvalidUser() {
        when(authenticationManager.authenticate(any())).thenThrow(new RuntimeException("Bad credentials"));
        ResponseEntity<?> res = authController.authenticateUser(login("nouser@example.com", "test123"));
        assertEquals(401, res.getStatusCodeValue());
    }

    @Test
    void testAuthenticate_WrongPassword() {
        when(authenticationManager.authenticate(any())).thenThrow(new RuntimeException("Bad credentials"));
        ResponseEntity<?> res = authController.authenticateUser(login("admin@example.com", "WrongPass"));
        assertEquals(401, res.getStatusCodeValue());
    }

    @Test
    void testAuthenticate_EmptyPassword() {
        LoginRequest req = login("admin@example.com", "");
        ResponseEntity<?> res = authController.authenticateUser(req);
        assertEquals(400, res.getStatusCodeValue());
    }

    @Test
    void testAuthenticate_TokenData() {
        Authentication auth = mock(Authentication.class);
        UserDetailsImpl details = new UserDetailsImpl(
                1L,
                "adminuser",
                "admin@example.com",
                "Admin",
                "User",
                "encoded-password",
                List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
        );

        when(authenticationManager.authenticate(any())).thenReturn(auth);
        when(auth.getPrincipal()).thenReturn(details);
        when(jwtUtils.generateJwtToken(any())).thenReturn("jwt-token");

        ResponseEntity<?> res = authController.authenticateUser(login("admin@example.com", "Admin123"));
        JwtResponse body = (JwtResponse) res.getBody();
        assertEquals("admin@example.com", body.getEmail());
        assertTrue(body.getRoles().contains("ROLE_ADMIN"));
    }

    // === UTC-02 ===

    @Test
    void testRegisterUser_OK() {
        SignupRequest s = validSignup("user");
        when(userRepository.existsByUsername(any())).thenReturn(false);
        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(Optional.of(new Role(ERole.ROLE_USER)));

        ResponseEntity<?> res = authController.registerUser(s);
        assertEquals(200, res.getStatusCodeValue());
    }

    @Test
    void testRegister_DuplicateEmail() {
        SignupRequest s = validSignup("user");
        when(userRepository.existsByUsername(any())).thenReturn(false);
        when(userRepository.existsByEmail(any())).thenReturn(true);

        ResponseEntity<?> res = authController.registerUser(s);
        assertEquals(400, res.getStatusCodeValue());
    }

    @Test
    void testRegister_DuplicateUsername() {
        SignupRequest s = validSignup("user");
        when(userRepository.existsByUsername(any())).thenReturn(true);

        ResponseEntity<?> res = authController.registerUser(s);
        assertEquals(400, res.getStatusCodeValue());
    }

    @Test
    void testRegister_ModeratorValidToken() {
        SignupRequest s = validSignup("moderator");
        s.setInvitationToken("MORU-INVITE-123");

        when(userRepository.existsByUsername(any())).thenReturn(false);
        when(userRepository.existsByEmail(any())).thenReturn(false);
        when(roleRepository.findByName(ERole.ROLE_MODERATOR)).thenReturn(Optional.of(new Role(ERole.ROLE_MODERATOR)));

        ResponseEntity<?> res = authController.registerUser(s);
        assertEquals(200, res.getStatusCodeValue());
    }

    @Test
    void testRegister_ModeratorInvalidToken() {
        SignupRequest s = validSignup("moderator");
        s.setInvitationToken("WRONG");

        ResponseEntity<?> res = authController.registerUser(s);
        assertEquals(400, res.getStatusCodeValue());
    }

    @Test
    void testRegister_MissingPassword() {
        SignupRequest s = validSignup("user");
        s.setPassword("");
        s.setConfirmPassword("");

        ResponseEntity<?> res = authController.registerUser(s);
        assertEquals(400, res.getStatusCodeValue());
    }
}
