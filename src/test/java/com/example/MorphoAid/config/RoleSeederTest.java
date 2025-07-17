package com.example.MorphoAid.config;

import com.example.MorphoAid.models.ERole;
import com.example.MorphoAid.models.Role;
import com.example.MorphoAid.repository.RoleRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
class RoleSeederTest {

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private RoleSeeder roleSeeder;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    // === UTC-12.1 ===
    @Test
    void testRun_allRolesMissing_shouldSaveAll() throws Exception {
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(Optional.empty());
        when(roleRepository.findByName(ERole.ROLE_MODERATOR)).thenReturn(Optional.empty());
        when(roleRepository.findByName(ERole.ROLE_ADMIN)).thenReturn(Optional.empty());

        roleSeeder.run();

        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository, times(3)).save(captor.capture());

        List<Role> savedRoles = captor.getAllValues();
        assertTrue(savedRoles.stream().anyMatch(r -> r.getName() == ERole.ROLE_USER));
        assertTrue(savedRoles.stream().anyMatch(r -> r.getName() == ERole.ROLE_MODERATOR));
        assertTrue(savedRoles.stream().anyMatch(r -> r.getName() == ERole.ROLE_ADMIN));
    }

    // === UTC-12.2 ===
    @Test
    void testRun_someRolesExist_shouldSaveOnlyMissing() throws Exception {
        when(roleRepository.findByName(ERole.ROLE_USER)).thenReturn(Optional.of(new Role(ERole.ROLE_USER)));
        when(roleRepository.findByName(ERole.ROLE_MODERATOR)).thenReturn(Optional.empty());
        when(roleRepository.findByName(ERole.ROLE_ADMIN)).thenReturn(Optional.of(new Role(ERole.ROLE_ADMIN)));

        roleSeeder.run();

        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepository, times(1)).save(captor.capture());

        Role saved = captor.getValue();
        assertEquals(ERole.ROLE_MODERATOR, saved.getName());
    }
}
