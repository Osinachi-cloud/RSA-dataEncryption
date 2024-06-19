package com.stitch;


import com.squareup.okhttp.OkHttpClient;
import com.squareup.okhttp.Request;
import com.squareup.okhttp.Response;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/*
    this is an assymetric encryption where data
    is being encrypted by the client using the public key
    and it is being decrypted by the application using the private key.
* **/

// this example is when the different apps needs to encrypt and decrypt

public class RSA {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private static final String PRIVATE_KEY_STRING = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJkyjZZTqnx1C0Bk/aUeN7g/VZdlps4aYSSvDnZLSU1Bt3xNirLn7nXP9mYvu/vV/rteAMTSgTeM1FajEehIvnOSwqQ7YNlmRUrs61i/WSkF2/sYz6qX7SSQB6BS/A9NvUm6YFER7crEFJxEgMYcVEqtBG7mJi4TgA6VD5C9rp33AgMBAAECgYBMlpVqXhGRfwJNAzA7aEv69M7ZjZxC1bVTHaFhSmovEXel0S5SGtmAVKOemqakVGuxSGGiBItNNj7BwWymcBel7r87ISkoxP7hL/BjstU7c+bS4/ubfMSBVwNvw3DMHVn2OLbKMoXE4WK9G2j8U2xG+lSZ8pSAjdEbSbTa02i1gQJBAOzDCn+P3a+uDaJt8ecBUNOtdcHtEdJE9lsIw1LX8BdoPqcvv67XlSAZZG9MZYm7KMNVnucchpHljRwL16EiRXECQQClpUMoU8vwycKBA/PGTWtMgspjbf4wE4VYrmzu4nYMv5dCOAPMCY5wcl6SHhhnhpSIDJpe/8DtwpCD28bMcsXnAkEAgVyP/+K7XaHcEUPBSFaPsxiznqHJevnzIQpIrpsNs7xhfze3o/BmqoM1PRqg4ABC5XeCuwP7AvxJfWl7B6+SAQJBAIdtNxvobst9WP18CrktILWcFPX3vqL1wsa/TKZ+Ff/UQElOXKRbh84dY35ZBqDVYehdTXSv6r84nEiBzeXnTC8CQGFu/NbiJod+i2kVMdUc5EP9ezqkz/nczoqBh+TKCCLsPB7aCGOdN+Orkr/GQYhRg9LZpLr9a7+2LOWYwYWYJcU=";
    private static final String PUBLIC_KEY_STRING = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCZMo2WU6p8dQtAZP2lHje4P1WXZabOGmEkrw52S0lNQbd8TYqy5+51z/ZmL7v71f67XgDE0oE3jNRWoxHoSL5zksKkO2DZZkVK7OtYv1kpBdv7GM+ql+0kkAegUvwPTb1JumBREe3KxBScRIDGHFRKrQRu5iYuE4AOlQ+Qva6d9wIDAQAB";

    public void init() throws Exception {
        // Initialize keys from strings
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY_STRING));
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY_STRING));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        publicKey = keyFactory.generatePublic(publicKeySpec);
        privateKey = keyFactory.generatePrivate(privateKeySpec);
    }

    public String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            RSA rsa = new RSA();
            rsa.init();
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url("http://localhost:8081/getSecretMessage")
                    .method("GET", null)
                    .build();

            Response response = client.newCall(request).execute();
            String encryptedMessage = response.body().string();

            System.err.println("Response body: " + encryptedMessage);

            String decryptedMessage = rsa.decrypt(encryptedMessage);

            System.err.println("Decrypted: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
