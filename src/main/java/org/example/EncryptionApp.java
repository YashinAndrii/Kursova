package org.example;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

public class EncryptionApp extends Application {

    private TextArea inputTextArea;
    private TextArea outputTextArea;

    @Override
    public void start(Stage primaryStage) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, IOException, InvalidKeyException {
        // Налаштування заголовка вікна
        primaryStage.setTitle("Шифрування і дешифрування");
        KeyStorage keyStorage = new KeyStorage();

        // Генерація випадкового секретного ключа
        SecretKey secretKey = keyStorage.generateKey();
        //keyStorage.saveKey(secretKey);

        // Створення елементів управління
        Label inputLabel = new Label("Введіть текст для шифрування:");
        inputTextArea = new TextArea();
        inputTextArea.setWrapText(true);
        inputTextArea.setPrefRowCount(5);

        Label outputLabel = new Label("Зашифрований текст:");
        outputTextArea = new TextArea();
        outputTextArea.setWrapText(true);
        outputTextArea.setPrefRowCount(5);
        outputTextArea.setEditable(false);

        Button encryptFileButton = new Button("Шифрувати файл");
        encryptFileButton.setOnAction(e -> {
            FileEncryptionApp fileEncryptionApp = new FileEncryptionApp();
            Stage stage = new Stage();
            fileEncryptionApp.start(stage);
        });

        Button encryptButton = generateButtonToEncrypt(secretKey);

        Button decryptButton = generateButtonToDecrypt(secretKey);

        // Налаштування макету
        VBox layout = new VBox(10);
        layout.setPadding(new Insets(10));
        layout.getChildren().addAll(inputLabel, inputTextArea, outputLabel, outputTextArea, encryptButton, decryptButton, encryptFileButton);

        // Відображення вікна
        primaryStage.setScene(new Scene(layout, 400, 300));
        primaryStage.show();
    }

    private String encryptText(String data, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedData);
    }
    private String decryptText(String encryptedData, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedData);
    }

    private SecretKey secretKeyGen() {
        // Генерація випадкового секретного ключа
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[16]; // 16 байт для ключа AES-128
        secureRandom.nextBytes(keyBytes);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Перетворення SecretKeySpec в SecretKey
        return new SecretKeySpec(secretKeySpec.getEncoded(), "AES");
    }

    private Button generateButtonToEncrypt(SecretKey secretKey) {
        Button encryptButton = new Button("Шифрувати");
        encryptButton.setOnAction(e -> {
            try {
                String originalData = inputTextArea.getText();
                SecretKey chosenKey = chooseKeyDialog(secretKey); // Виклик діалогового вікна для вибору ключа
                if (chosenKey != null) {
                    String encryptedData = encryptText(originalData, chosenKey);
                    outputTextArea.setText(encryptedData);
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        return encryptButton;
    }

    private SecretKey chooseKeyDialog(SecretKey existingKey) {
        // Створення діалогового вікна для вибору ключа
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Вибір ключа");
        alert.setHeaderText("Виберіть, який ключ використовувати:");
        alert.setContentText("Використати існуючий ключ, або згенерувати новий?");

        // Додавання кнопок "Використати існуючий ключ" та "Згенерувати новий ключ"
        ButtonType existingKeyButton = new ButtonType("Використати існуючий ключ");
        ButtonType generateKeyButton = new ButtonType("Згенерувати новий ключ");

        alert.getButtonTypes().setAll(existingKeyButton, generateKeyButton);

        Optional<ButtonType> result = alert.showAndWait();
        if (result.isPresent() && result.get() == existingKeyButton) {
            // Відкриття діалогового вікна для введення кодового слова
            TextInputDialog dialog = new TextInputDialog();
            dialog.setTitle("Введіть кодове слово");
            dialog.setHeaderText("Введіть кодове слово для використання існуючого ключа:");
            dialog.setContentText("Кодове слово:");

            Optional<String> passwordResult = dialog.showAndWait();
            if (passwordResult.isPresent()) {
                // Перевірка, чи введене кодове слово вірне
                String password = passwordResult.get();
                if (checkPassword(password)) {
                    return existingKey; // Повертаємо існуючий ключ
                } else {
                    showAlert("Помилка", "Невірне кодове слово!", Alert.AlertType.ERROR);
                    return null; // Повертаємо null, якщо кодове слово невірне
                }
            } else {
                return null; // Повертаємо null, якщо користувач скасував введення кодового слова
            }
        } else {
            return secretKeyGen(); // Повертаємо новий ключ
        }
    }

    private boolean checkPassword(String password) {
        // Тут можна реалізувати логіку перевірки кодового слова
        // Наприклад, можна зробити перевірку на довжину або на певний паттерн
        // У цьому прикладі ми просто перевіряємо, чи кодове слово складається з 6 символів
        return password.length() == 6;
    }

    private void showAlert(String title, String message, Alert.AlertType alertType) {
        Alert alert = new Alert(alertType);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private Button generateButtonToDecrypt(SecretKey secretKey) {
        Button decryptButton = new Button("Дешифрувати");
        decryptButton.setOnAction(e -> {
            try {
                String encryptedData = outputTextArea.getText();
                String decryptedData = decryptText(encryptedData, secretKey);
                outputTextArea.setText(decryptedData);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        });

        return decryptButton;
    }


    public static void main(String[] args) {
        launch(args);
    }
}

