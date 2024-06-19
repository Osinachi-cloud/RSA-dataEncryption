package com.stitch;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

/*
    this is an assymetric encryption where data
    is being encrypted by the client using the public key
    and it is being decrypted by the application using the private key.
* **/
public class RSA {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSA() {
        try{
            // to generate a public and private key instance you need KeyPairGenerator
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            KeyPair pair = generator.generateKeyPair();
            privateKey = pair.getPrivate();
            publicKey = pair.getPublic();
        }catch (NoSuchAlgorithmException e){
            throw new RuntimeException(e.getMessage());
        }
    }

    public String encrypt(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
       // first needs to convert the data to be encrypted to a byte array;
        byte[]  messageToBytes = message.getBytes();
        // initialize the cipher that does the encryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        // indicate that it is the encryption and pass in the public key.
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);

        // takes in the byte array the encode to String using base64
        return encode(encryptedBytes);
    }

    private String encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public String decrypt(String encryptedMessage) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
       // first decode using base 64 from string to byte array.
        byte [] encryptedBytes = decode(encryptedMessage);

        //initialize the cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // indicate that it is a decryption mode and pass in the private key to decrypt.
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte [] decryptedMessage = cipher.doFinal(encryptedBytes);

        // convert to a string
        return new String(decryptedMessage, "UTF8");
    }

    private byte[] decode(String data){
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        System.out.println("Hello world!");

        RSA rsa = new RSA();
        try{
           String encryptedMessage =  rsa.encrypt("hello world");
           String decryptedMessage = rsa.decrypt(encryptedMessage);

            System.err.println(encryptedMessage);
            System.err.println(decryptedMessage);
        }catch (Exception e){
            throw new RuntimeException(e.getMessage());
        }


    }
}
