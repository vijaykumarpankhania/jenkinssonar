    }

    @GetMapping("/redirect")
    public ResponseEntity<Void> redirect(@RequestParam String url) {
        try {
            URI uri = URI.create(url);
            boolean valid =
                    "https".equalsIgnoreCase(uri.getScheme())
                    && "trustedsite.com".equalsIgnoreCase(uri.getHost())
                    && uri.getRawUserInfo() == null
                    && (uri.getPort() == -1 || uri.getPort() == 443);

            if (!valid) {
                return ResponseEntity.badRequest().build();
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(uri);
            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(
            @RequestParam String username,
            @RequestParam String password) {
        if (username.isBlank() || password.isEmpty()
                || username.length() > 100 || password.length() > 72) {
            return ResponseEntity.badRequest().body("Invalid credentials.");
        }

        try {
            String storedHash = getUserPassword(username);
            if (storedHash != null && PASSWORD_ENCODER.matches(password, storedHash)) {
                return ResponseEntity.ok("Login successful!");
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid credentials.");
        } catch (SQLException ex) {
            logger.error("Database error during login", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Login is temporarily unavailable.");
        }
    }

    @GetMapping("/fetchUser")
    public ResponseEntity<String> fetchUser(@RequestParam String username) {
        if (username.isBlank() || username.length() > 100) {
            return ResponseEntity.badRequest().body("Invalid username.");
        }

        String sql = "SELECT username FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(databaseUrl, databaseUser, databasePassword);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return ResponseEntity.ok(
                            "User found: " + escapeHtml(rs.getString("username")));
                }
            }
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found.");
        } catch (SQLException ex) {
            logger.error("Database error while fetching user", ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Database error.");
        }
    }

    private String getUserPassword(String username) throws SQLException {
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(databaseUrl, databaseUser, databasePassword);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, username);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getString("password_hash");
                }
            }
        }
        return null;
    }

    private String escapeHtml(String input) {
        if (input == null) {
            return "";
        }

        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }
}
