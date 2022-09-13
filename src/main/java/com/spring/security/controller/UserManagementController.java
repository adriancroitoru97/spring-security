package com.spring.security.controller;

import com.spring.security.dto.User;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/users")
public class UserManagementController {
    private static final List<User> USERS_LIST = Arrays.asList(
            new User(1, "User1"),
            new User(2, "User2"),
            new User(3, "Admin"));

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_ADMINTRAINEE')")
    public List<User> getAllUsers() {
        System.out.println("getAllUsers");
        return USERS_LIST;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('employee:write')")
    public void registerNewUser(@RequestBody User user) {
        System.out.println("registerNewUser");
        System.out.println(user);
    }

    @DeleteMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('employee:write')")
    public void deleteUser(@PathVariable("studentId") Integer userId) {
        System.out.println("deleteUser");
        System.out.println(userId);
    }

    @PutMapping(path = "{studentId}")
    @PreAuthorize("hasAuthority('employee:write')")
    public void updateUser(@PathVariable("studentId") Integer userId, @RequestBody User user) {
        System.out.println("updateUser");
        System.out.printf("%s %s%n", userId, user);
    }
}
