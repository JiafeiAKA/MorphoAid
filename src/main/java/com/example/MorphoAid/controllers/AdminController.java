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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;


    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> getUsersWithPagination(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        Pageable paging = PageRequest.of(page, size);
        Page<User> pagedUsers = userRepository.findAll(paging);

        List<UserWithRolesResponse> users = pagedUsers.getContent().stream().map(user ->
                new UserWithRolesResponse(
                        user.getId(),
                        user.getUsername(),
                        user.getEmail(),
                        user.getFirstName(),
                        user.getLastName(),
                        user.getRoles().stream().map(role -> role.getName().name()).collect(Collectors.toList())
                )
        ).toList();

        return ResponseEntity.ok(Map.of(
                "users", users,
                "currentPage", pagedUsers.getNumber(),
                "totalPages", pagedUsers.getTotalPages(),
                "totalUsers", pagedUsers.getTotalElements()
        ));
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
