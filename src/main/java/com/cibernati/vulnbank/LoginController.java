package com.cibernati.vulnbank;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class LoginController {

    private final UserRepository users;

    public LoginController(UserRepository users) {
        this.users = users;
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        List<Map<String, Object>> found = users.login(username, password);
        if (found.isEmpty()) {
            return Map.of("ok", false, "message", "Credenciales invalidas");
        }
        return Map.of("ok", true, "user", found.get(0));
    }
}
