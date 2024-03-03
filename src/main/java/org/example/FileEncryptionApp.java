package org.example;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
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

public class FileEncryptionApp extends Application {

    private TextField filePathTextField;
    private TextArea outputTextArea;

    @Override
    public void start(Stage primaryStage) {
        // Налаштування заголовка вікна
        primaryStage.setTitle("Шифрування файлів");

        // Створення елементів управління
        Label filePathLabel = new Label("Шлях до файлу:");
        filePathTextField = new TextField();
        filePathTextField.setPrefWidth(200);

        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[16]; // 16 байт для ключа AES-128
        secureRandom.nextBytes(keyBytes);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        // Перетворення SecretKeySpec в SecretKey
        SecretKey secretKey = new SecretKeySpec(secretKeySpec.getEncoded(), "AES");

        Button browseButton = new Button("Оберіть файл");
        browseButton.setOnAction(e -> browseFile());

        Button encryptButton = new Button("Зашифрувати");
        encryptButton.setOnAction(e -> encryptFile(secretKey));

        Button decryptButton = new Button("Розшифрувати");
        decryptButton.setOnAction(e -> decryptFile(secretKey));

        Label outputLabel = new Label("Статус:");
        outputTextArea = new TextArea();
        outputTextArea.setPrefRowCount(3);
        outputTextArea.setEditable(false);

        // Налаштування макету
        VBox layout = new VBox(10);
        layout.setPadding(new Insets(10));
        layout.getChildren().addAll(filePathLabel, filePathTextField, browseButton, encryptButton, decryptButton, outputLabel, outputTextArea);

        // Відображення вікна
        primaryStage.setScene(new Scene(layout, 400, 300));
        primaryStage.show();
    }

    private void browseFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Оберіть файл для шифрування");
        File selectedFile = fileChooser.showOpenDialog(null);
        if (selectedFile != null) {
            filePathTextField.setText(selectedFile.getAbsolutePath());
        }
    }

    private void encryptFile(SecretKey secretKeySpec) {
        String filePath = filePathTextField.getText();
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            outputTextArea.setText("Файл не знайдено.");
            return;
        }

        try {
            // Зашифрувати файл
            File encryptedFile = new File(inputFile.getParent(), "encrypted_" + inputFile.getName());
            encryptFile(inputFile, encryptedFile, secretKeySpec);
            outputTextArea.setText("Файл зашифровано успішно.");
        } catch (Exception e) {
            outputTextArea.setText("Помилка під час шифрування файлу: " + e.getMessage());
        }
    }

    private void decryptFile(SecretKey secretKeySpec) {
        String filePath = filePathTextField.getText();
        File inputFile = new File(filePath);
        if (!inputFile.exists()) {
            outputTextArea.setText("Файл не знайдено.");
            return;
        }

        try {
            // Зашифрувати файл
            File decryptedFile = new File(inputFile.getParent(), "decrypted_" + inputFile.getName());
            decryptFile(inputFile, decryptedFile, secretKeySpec);
            outputTextArea.setText("Файл розшифровано успішно.");
        } catch (Exception e) {
            outputTextArea.setText("Помилка під час розшифрування файлу: " + e.getMessage());
        }
    }

    private void encryptFile(File inputFile, File outputFile, SecretKey secretKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] encryptedBytes = cipher.doFinal(inputBytes);
            outputStream.write(encryptedBytes);
        }
    }

    private void decryptFile(File inputFile, File outputFile, SecretKey secretKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (FileInputStream inputStream = new FileInputStream(inputFile);
             FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            byte[] inputBytes = new byte[(int) inputFile.length()];
            inputStream.read(inputBytes);

            byte[] decryptedBytes = cipher.doFinal(inputBytes);
            outputStream.write(decryptedBytes);
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}

