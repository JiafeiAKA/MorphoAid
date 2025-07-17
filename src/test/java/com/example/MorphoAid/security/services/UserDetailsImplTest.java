package com.example.MorphoAid.security.services;

import com.example.MorphoAid.models.ERole;
import com.example.MorphoAid.models.Role;
import com.example.MorphoAid.models.User;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

public class UserDetailsImplTest {

    private User createUser(Set<ERole> roles) {
        User user = new User();
        user.setId(1L);
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setPassword("password123");
        user.setFirstName("Test");
        user.setLastName("User");

        user.setRoles(roles.stream().map(Role::new).collect(Collectors.toSet()));
        return user;
    }

    @Test
    void testBuild_withRoles_shouldReturnCorrectAuthorities() {
        // UTC-09.1
        User userOneRole = createUser(Set.of(ERole.ROLE_USER));
        UserDetailsImpl details1 = UserDetailsImpl.build(userOneRole);
        assertEquals(1, details1.getAuthorities().size());
        assertTrue(details1.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));

        // UTC-09.2
        User userMultiRole = createUser(Set.of(ERole.ROLE_USER, ERole.ROLE_ADMIN));
        UserDetailsImpl details2 = UserDetailsImpl.build(userMultiRole);
        assertEquals(2, details2.getAuthorities().size());
        assertTrue(details2.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
        assertTrue(details2.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN")));
    }

    @Test
    void testUserDetailsImpl_gettersAndStatus_shouldReturnCorrectValues() {
        UserDetailsImpl user = new UserDetailsImpl(
                2L,
                "john_doe",
                "john@example.com",
                "securePass",
                "John",
                "Doe",
                Set.of(() -> "ROLE_USER")
        );

        // UTC-10.1 to 10.3
        assertEquals("john@example.com", user.getEmail());
        assertEquals("john_doe", user.getUsername());
        assertTrue(user.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER")));

        // UTC-10.4 to 10.7
        assertTrue(user.isAccountNonExpired());
        assertTrue(user.isAccountNonLocked());
        assertTrue(user.isCredentialsNonExpired());
        assertTrue(user.isEnabled());
    }
}
