
package com.example.MorphoAid.controllers;

import com.example.MorphoAid.DTO.request.UpdateUserRoleRequest;
import com.example.MorphoAid.models.ERole;
import com.example.MorphoAid.models.Role;
import com.example.MorphoAid.models.User;
import com.example.MorphoAid.repository.RoleRepository;
import com.example.MorphoAid.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
public class AdminControllerTest {

    @Mock private UserRepository userRepository;
    @Mock private RoleRepository roleRepository;
    @InjectMocks private AdminController adminController;

    private User createUserWithRoles(Long id, String username, ERole... roles) {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setEmail(username + "@mail.com");
        user.setFirstName("First");
        user.setLastName("Last");

        Set<Role> roleSet = new HashSet<>();
        for (ERole r : roles) {
            roleSet.add(new Role(r));
        }
        user.setRoles(roleSet);
        return user;
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // === UTC-03 ===

    @Test
    void testGetAllUsersWithRoles_asAdmin_shouldReturnList() {
        List<User> mockUsers = List.of(
                createUserWithRoles(1L, "adminuser", ERole.ROLE_ADMIN),
                createUserWithRoles(2L, "normaluser", ERole.ROLE_USER)
        );
        when(userRepository.findAll()).thenReturn(mockUsers);

        ResponseEntity<?> response = adminController.getAllUsersWithRoles();
        assertEquals(200, response.getStatusCodeValue());
        assertTrue(response.getBody() instanceof List<?>);
    }

    // === UTC-04 ===

    @Test
    void testUpdateUserRole_validRole_shouldUpdate() {
        User user = createUserWithRoles(1L, "user1", ERole.ROLE_USER);
        UpdateUserRoleRequest req = new UpdateUserRoleRequest();
        req.setRole("user");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(Optional.of(new Role(ERole.ROLE_USER)));
        when(userRepository.save(any())).thenReturn(user);

        ResponseEntity<?> res = adminController.updateUserRole(1L, req);
        assertEquals(200, res.getStatusCodeValue());
        assertEquals("User role updated successfully.", res.getBody());
    }

    @Test
    void testUpdateUserRole_userNotFound_shouldThrow() {
        UpdateUserRoleRequest req = new UpdateUserRoleRequest();
        req.setRole("user");

        when(userRepository.findById(999L)).thenReturn(Optional.empty());

        Exception exception = assertThrows(RuntimeException.class, () -> {
            adminController.updateUserRole(999L, req);
        });
        assertTrue(exception.getMessage().contains("User not found"));
    }

    @Test
    void testUpdateUserRole_roleNotFound_shouldThrow() {
        User user = createUserWithRoles(1L, "user1", ERole.ROLE_USER);
        UpdateUserRoleRequest req = new UpdateUserRoleRequest();
        req.setRole("invalidRole");

        when(userRepository.findById(1L)).thenReturn(Optional.of(user));

        Exception exception = assertThrows(RuntimeException.class, () -> {
            adminController.updateUserRole(1L, req);
        });

        assertTrue(exception.getMessage().contains("Invalid role: invalidRole"));
    }


    // === UTC-05 ===

    @Test
    void testDeleteUser_exists_shouldDelete() {
        when(userRepository.existsById(1L)).thenReturn(true);
        doNothing().when(userRepository).deleteById(1L);

        ResponseEntity<?> res = adminController.deleteUser(1L);
        assertEquals(200, res.getStatusCodeValue());
        assertEquals("User deleted successfully.", res.getBody());
    }

    @Test
    void testDeleteUser_notFound_shouldReturn404() {
        when(userRepository.existsById(999L)).thenReturn(false);

        ResponseEntity<?> res = adminController.deleteUser(999L);
        assertEquals(404, res.getStatusCodeValue());
    }
}
