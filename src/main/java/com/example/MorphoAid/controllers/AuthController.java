package com.example.MorphoAid.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.MorphoAid.models.ERole;
import com.example.MorphoAid.models.Role;
import com.example.MorphoAid.models.User;
import com.example.MorphoAid.DTO.request.LoginRequest;
import com.example.MorphoAid.DTO.request.SignupRequest;
import com.example.MorphoAid.DTO.response.JwtResponse;
import com.example.MorphoAid.DTO.response.MessageResponse;
import com.example.MorphoAid.repository.RoleRepository;
import com.example.MorphoAid.repository.UserRepository;
import com.example.MorphoAid.security.jwt.JwtUtils;
import com.example.MorphoAid.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    JwtUtils jwtUtils;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        // ✅ Email format validation
        if (loginRequest.getEmail() == null || !loginRequest.getEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email is invalid"));
        }

        // ✅ Password blank check
        if (loginRequest.getPassword() == null || loginRequest.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Password must not be blank"));
        }

        // ✅ Perform authentication
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwt = jwtUtils.generateJwtToken(authentication);

            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
            List<String> roles = userDetails.getAuthorities().stream()
                    .map(item -> item.getAuthority())
                    .collect(Collectors.toList());

            // ✅ Determine role-based redirection
            String redirectUrl = "/dashboard";  // fallback default
            if (roles.contains("ROLE_ADMIN")) {
                redirectUrl = "/admin/dashboard";
            } else if (roles.contains("ROLE_MODERATOR")) {
                redirectUrl = "/moderator/dashboard";
            } else if (roles.contains("ROLE_USER")) {
                redirectUrl = "/user/dashboard";
            }

            return ResponseEntity.ok(new JwtResponse(
                    jwt,
                    userDetails.getId(),
                    userDetails.getEmail(),
                    userDetails.getFirstName(),
                    userDetails.getLastName(),
                    roles,
                    redirectUrl
            ));

        } catch (Exception e) {
            return ResponseEntity.status(401).body(new MessageResponse("Invalid credentials"));
        }
    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        // Validate required fields
        if (signUpRequest.getUsername() == null || signUpRequest.getUsername().trim().isEmpty()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username must not be blank"));
        }

        if (signUpRequest.getEmail() == null || !signUpRequest.getEmail().matches("^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$")) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email is invalid"));
        }

        if (signUpRequest.getPassword() == null || signUpRequest.getPassword().isEmpty()) {
            return ResponseEntity.badRequest().body(new MessageResponse("Password must not be blank"));
        }

        if (!signUpRequest.getPassword().equals(signUpRequest.getConfirmPassword())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Passwords do not match"));
        }

        if (signUpRequest.getAgree() == null || !signUpRequest.getAgree()) {
            return ResponseEntity.badRequest().body(new MessageResponse("You must agree to terms and privacy policy"));
        }

        // Username length: min 4, max 10
        if (signUpRequest.getUsername().length() < 4) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username have a minimum of 4 characters"));
        }

        if (signUpRequest.getUsername().length() > 10) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username limit at 10 characters"));
        }

        // Password length: min 6, max 20
        if (signUpRequest.getPassword().length() < 6) {
            return ResponseEntity.badRequest().body(new MessageResponse("Password have a minimum of 6 characters"));
        }

        if (signUpRequest.getPassword().length() > 20) {
            return ResponseEntity.badRequest().body(new MessageResponse("Password limit at 20 characters"));
        }

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Email is already in use!"));
        }

        // Validate invitation token if role = moderator
        if ("moderator".equals(signUpRequest.getRoles())) {
            if (signUpRequest.getInvitationToken() == null || !signUpRequest.getInvitationToken().equals("MORU-INVITE-123")) {
                return ResponseEntity.badRequest().body(new MessageResponse("Invalid invitation token for MORU."));
            }
        }

        // Create new user
        User user = new User(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()),
                signUpRequest.getFirstName(),
                signUpRequest.getLastName()
        );

        // Assign roles
        Set<Role> roles = new HashSet<>();
        String selectedRole = signUpRequest.getRoles();

        switch (selectedRole) {
            case "admin":
                Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                        .orElseThrow(() -> new RuntimeException("Role ADMIN not found."));
                roles.add(adminRole);
                break;
            case "moderator":
                Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                        .orElseThrow(() -> new RuntimeException("Role MODERATOR not found."));
                roles.add(modRole);
                break;
            default:
                Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                        .orElseThrow(() -> new RuntimeException("Role USER not found."));
                roles.add(userRole);
        }

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

}