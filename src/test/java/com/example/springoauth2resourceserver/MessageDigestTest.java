package com.example.springoauth2resourceserver;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class MessageDigestTest {

    @Test
    void test() throws Exception {
        String message = "check";
        createMD5(message);
        validateMD5(message);
    }

    private void createMD5(String message)
        throws NoSuchAlgorithmException, IOException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[10];
        random.nextBytes(salt);

        MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.update(salt);
        messageDigest.update(message.getBytes("UTF-8"));

        byte[] digest = messageDigest.digest();

        FileOutputStream fileOutputStream = new FileOutputStream("message.txt");
        fileOutputStream.write(salt);
        fileOutputStream.write(digest);
        fileOutputStream.close();
    }

    public void validateMD5(String message) throws Exception {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream("message.txt");
        int theByte;
        while ((theByte = fis.read()) != -1) {
            byteArrayOutputStream.write(theByte);
        }
        fis.close();
        byte[] hashedMessage = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.reset();

        byte[] salt = new byte[10];
        System.arraycopy(hashedMessage, 0, salt, 0, 10);
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(salt);
        md.update(message.getBytes("UTF-8"));
        byte[] digest = md.digest();

        byte[] digestInFile = new byte[hashedMessage.length - 10];
        System.arraycopy(hashedMessage, 10, digestInFile, 0, hashedMessage.length - 10);

        if (Arrays.equals(digest, digestInFile)) {
            System.out.println("message matches.");
        } else {
            System.out.println("message does not matches.");
        }

        new File("message.txt").delete();
    }
}


