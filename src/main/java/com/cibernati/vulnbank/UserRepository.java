package com.cibernati.vulnbank;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class UserRepository {

    private final JdbcTemplate jdbc;

    public UserRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> login(String username, String password) {
        String sql = "SELECT id, username, balance, role FROM users " +
                "WHERE username = '" + username + "' AND password = '" + password + "'";
        return jdbc.queryForList(sql);
    }
}
