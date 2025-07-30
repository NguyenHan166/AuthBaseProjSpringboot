package com.nguyenhan.authbasedproject.init;

import com.nguyenhan.authbasedproject.constant.role.ERole;
import com.nguyenhan.authbasedproject.entity.Role;
import com.nguyenhan.authbasedproject.entity.User;
import com.nguyenhan.authbasedproject.repository.RoleRepository;
import com.nguyenhan.authbasedproject.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Slf4j
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        // Initialize roles if they don't exist
        if (roleRepository.count() == 0) {
            roleRepository.save(new Role(ERole.ROLE_USER));
            roleRepository.save(new Role(ERole.ROLE_EMPLOYEE));
            roleRepository.save(new Role(ERole.ROLE_ADMIN));
        }

        // Create default admin user if doesn't exist
        if (!userRepository.existsByUsername("admin")) {
            User admin = new User("admin", "admin@example.com", passwordEncoder.encode("admin123"));
            log.atInfo().log("Admin logged in " + passwordEncoder.encode("admin123"));
            Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Admin role not found"));
            admin.setRoles(Set.of(adminRole));
            userRepository.save(admin);
        }

        // Create default employee user if doesn't exist
        if (!userRepository.existsByUsername("employee")) {
            User employee = new User("employee", "employee@example.com", passwordEncoder.encode("employee123"));
            Role employeeRole = roleRepository.findByName(ERole.ROLE_EMPLOYEE)
                    .orElseThrow(() -> new RuntimeException("Employee role not found"));
            employee.setRoles(Set.of(employeeRole));
            userRepository.save(employee);
        }

        // Create default user if doesn't exist
        if (!userRepository.existsByUsername("user")) {
            User user = new User("user", "user@example.com", passwordEncoder.encode("user123"));
            log.atInfo().log("User logged in " + passwordEncoder.encode("user123"));
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("User role not found"));
            user.setRoles(Set.of(userRole));
            userRepository.save(user);
        }
    }
}