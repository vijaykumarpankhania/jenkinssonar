package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

@SpringBootApplication
@RestController
public class WebProjectApplication {

    @Value("${database.url}")
    private String databaseUrl;

    @Value("${database.user}")
    private String databaseUser;

    @Value("${database.password}")
    private String databasePassword;

    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public static void main(String[] args) {
        SpringApplication.run(WebProjectApplication.class, args);
    }

    @GetMapping("/")
    public String home() {
        String riskyString = "SafeString"; // Fixed Null Pointer Exception
        int length = riskyString.length();

        return "<html>" +
                "<head><title>CloudFolks HUB</title></head>" +
                "<body style='text-align:center; background-color:#f0f8ff;'>" +
                "<h1 style='color: #4CAF50;'>Welcome to <span style='color: #00008B;'>CloudFolks HUB</span>!</h1>" +
                "<p style='font-size:20px; color: #555;'>Empowering Your DevOps Journey</p>" +
                "<form id='form' method='post' action='/submit' style='margin-top:20px;'>" +
                "<label for='name'>Name:</label><br>" +
                "<input type='text' id='name' name='name' required><br><br>" +
                "<label for='email'>Email:</label><br>" +
                "<input type='email' id='email' name='email' required><br><br>" +
                "<button type='submit'>Submit</button>" +
                "</form>" +
                "</body>" +
                "</html>";
    }

    @PostMapping("/submit")
    public String submit(@RequestParam String name, @RequestParam String email) {
        return "<html>" +
                "<head><title>Form Submitted</title></head>" +
                "<body style='text-align:center; background-color:#f0f8ff;'>" +
                "<h1 style='color: #4CAF50;'>Thank You, " + escapeHtml(name) + "!</h1>" +
                "<p style='font-size:20px; color: #555;'>Your email (" + escapeHtml(email) + ") has been submitted successfully.</p>" +
                "</body>" +
                "</html>";
    }

    @GetMapping("/redirect")
    public String redirect(@RequestParam String url) {
        if (!isValidRedirect(url)) {
            return "Invalid Redirect URL!";
        }
        return "<script>window.location.href='" + url + "'</script>";
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        // Secure Password Verification using BCrypt
        String storedHashedPassword = getUserPassword(username);
        if (storedHashedPassword != null && passwordEncoder.matches(password, storedHashedPassword)) {
            return "Login Successful!";
        }
        return "Invalid Credentials!";
    }

    @GetMapping("/fetchUser")
    public String fetchUser(@RequestParam String username) {
        try (Connection conn = DriverManager.getConnection(databaseUrl, databaseUser, databasePassword);
             PreparedStatement stmt = conn.prepareStatement("SELECT username FROM users WHERE username = ?")) {
            
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return "User found: " + escapeHtml(rs.getString("username"));
            }
        } catch (Exception e) {
            return "Database Error!";
        }
        return "User not found";
    }

    // Utility: Escapes HTML to prevent XSS attacks
    private String escapeHtml(String input) {
        return input.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
    }

    // Utility: Check if URL is whitelisted
    private boolean isValidRedirect(String url) {
        return url.startsWith("https://trustedsite.com");
    }

    // Utility: Fetch hashed password from DB (Simulation)
    private String getUserPassword(String username) {
        // In a real application, fetch hashed password from DB
        return passwordEncoder.encode("securepassword");
    }
}
