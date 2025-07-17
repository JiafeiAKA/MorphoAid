
package com.example.MorphoAid.security.services;

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
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserDetailsServiceImpl userDetailsService;

    @BeforeEach
    void init() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testLoadUserByUsername_shouldReturnUserDetailsIfEmailExists() {
        User user = new User();
        user.setId(1L);
        user.setEmail("test@example.com");
        user.setUsername("testuser");
        user.setPassword("secure");
        user.setFirstName("First");
        user.setLastName("Last");
        user.setRoles(Set.of(new Role(ERole.ROLE_USER)));

        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));

        UserDetailsImpl details = (UserDetailsImpl) userDetailsService.loadUserByUsername("test@example.com");

        assertEquals("test@example.com", details.getEmail());
        assertTrue(details.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_USER")));
    }

    @Test
    void testLoadUserByUsername_shouldThrowIfEmailNotFound() {
        when(userRepository.findByEmail("notfound@mail.com")).thenReturn(Optional.empty());

        Exception exception = assertThrows(UsernameNotFoundException.class, () ->
                userDetailsService.loadUserByUsername("notfound@mail.com"));

        assertTrue(exception.getMessage().contains("User Not Found with email"));
    }
}
