package org.example;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
public class KeyStorage {

    // З'єднання з базою даних
    private Connection connect() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/test";
        String user = "root";
        String password = "16122002aY";
        return DriverManager.getConnection(url, user, password);
    }

    public void saveKey(SecretKey secretKey) {
        String sql = "INSERT INTO `keys` (key_data) VALUES (?)";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setBytes(1, secretKey.getEncoded());
            pstmt.executeUpdate();
            System.out.println("Key saved successfully!");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    // Метод для генерації та збереження секретного ключа
    public SecretKey generateKey() {
        // Генерація випадкового секретного ключа
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[16]; // 16 байт для ключа AES-128
        secureRandom.nextBytes(keyBytes);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Перетворення SecretKeySpec в SecretKey
        SecretKey secretKey = new SecretKeySpec(secretKeySpec.getEncoded(), "AES");

        return secretKey;
    }

    // Метод для отримання секретного ключа з бази даних
    public SecretKey getKey() {
        String sql = "SELECT key_data FROM `keys` WHERE id = ?";
        try (Connection conn = connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setInt(1, 7); // Параметр key_id, змініть його за необхідності
            ResultSet rs = pstmt.executeQuery();
            System.out.println(rs);
            if (rs.next()) {
                byte[] keyBytes = rs.getBytes("key_data");
                return new SecretKeySpec(keyBytes, "AES");
            }
        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
        return null;
    }
}
