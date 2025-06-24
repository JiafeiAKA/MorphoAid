package com.example.MorphoAid.controllers;

import com.example.MorphoAid.models.User;
import com.example.MorphoAid.payload.response.UserWithRolesResponse;
import com.example.MorphoAid.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@CrossOrigin(origins = "*")
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    // ✅ GET /api/admin/users (ต้องเป็น ADMIN เท่านั้น)
    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getAllUsersWithRoles() {
        List<User> users = userRepository.findAll();

        List<UserWithRolesResponse> response = users.stream().map(user ->
                new UserWithRolesResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getRoles().stream().map(role -> role.getName().name()).collect(Collectors.toList())
                )
        ).collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }
}
