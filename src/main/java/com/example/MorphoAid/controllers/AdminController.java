package com.example.MorphoAid.controllers;

import com.example.MorphoAid.models.ERole;
import com.example.MorphoAid.models.Role;
import com.example.MorphoAid.models.User;
import com.example.MorphoAid.DTO.request.UpdateUserRoleRequest;
import com.example.MorphoAid.DTO.response.UserWithRolesResponse;
import com.example.MorphoAid.repository.RoleRepository;
import com.example.MorphoAid.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;


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

    @PutMapping("/users/{id}/role")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateUserRole(@PathVariable Long id, @RequestBody UpdateUserRoleRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        user.getRoles().clear();

        try {
            // 🔹 ป้องกัน null และ trim ข้อมูล
            String roleString = request.getRole();
            if (roleString == null || roleString.trim().isEmpty()) {
                throw new RuntimeException("Role string is empty");
            }

            // 🔹 ปรับให้รองรับทั้งแบบ "admin", "ADMIN", "Role_admin", ฯลฯ
            String roleFormatted = "ROLE_" + roleString.trim().toUpperCase();
            ERole targetRole = ERole.valueOf(request.getRole().toUpperCase());
            Role newRole = roleRepository.findByName(targetRole)
                    .orElseThrow(() -> new RuntimeException("Role not found in DB: " + targetRole.name()));

            user.getRoles().add(newRole);
            userRepository.save(user);

            return ResponseEntity.ok("User role updated to " + targetRole.name());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body("Invalid role: " + request.getRole());
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }



    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id) {
        if (!userRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }

        userRepository.deleteById(id);
        return ResponseEntity.ok("User deleted successfully.");
    }

}
