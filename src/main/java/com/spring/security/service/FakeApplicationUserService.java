package com.spring.security.service;

import com.google.common.collect.Lists;
import com.spring.security.dto.ApplicationUser;
import com.spring.security.dto.ApplicationUserDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.spring.security.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {

        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser("user1",
                        passwordEncoder.encode("pass1"),
                        EMPLOYEE.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser("admin",
                        passwordEncoder.encode("pass123"),
                        ADMIN.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true),
                new ApplicationUser("trainee",
                        passwordEncoder.encode("pass123"),
                        ADMINTRAINEE.getGrantedAuthority(),
                        true,
                        true,
                        true,
                        true)
        );

        return applicationUsers;
    }
}
