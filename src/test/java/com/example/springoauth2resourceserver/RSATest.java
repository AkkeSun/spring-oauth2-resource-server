package com.example.springoauth2resourceserver;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import org.junit.jupiter.api.Test;

public class RSATest {

    @Test
    void test() throws Exception {

        String message = "hello world";
        KeyPair keyPair = genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        String encrypted = encrypt(message, publicKey);
        String decrypted = decrypt(encrypted, privateKey);

        System.out.println("message : " + message);
        System.out.println("decrypted : " + decrypted);

        // 키 스펙 전환하기 (Key -> Base64)
        byte[] bytePublicKey = publicKey.getEncoded();
        String base64PublicKey = Base64.getEncoder().encodeToString(bytePublicKey);
        byte[] bytePrivateKey = privateKey.getEncoded();
        String base64PrivateKey = Base64.getEncoder().encodeToString(bytePrivateKey);

        // base64PublicKey -> PublicKey
        PublicKey X509PublicKey = getPublicKeyFromKeySpec(base64PublicKey);
        String encrypted2 = encrypt(message, X509PublicKey);
        String decrypted2 = decrypt(encrypted2, privateKey);

        System.out.println("message : " + message);
        System.out.println("decrypted2 : " + decrypted2);

        // base64PrivateKey -> PrivateKey
        PrivateKey PKCS8PrivateKey = getPrivateKeyFromKeySpec(base64PrivateKey);
        String decrypted3 = decrypt(encrypted2, PKCS8PrivateKey);

        System.out.println("message : " + message);
        System.out.println("decrypted3 : " + decrypted3);
    }

    // 비대칭키 생성하기
    KeyPair genKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(1024, new SecureRandom());
        return gen.genKeyPair();
    }

    // 암호화
    String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytePlain = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(bytePlain);
    }

    // 복호화
    String decrypt(String encrypted, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytePlain = cipher.doFinal(byteEncrypted);
        return new String(bytePlain, "utf-8");
    }

    // base64PublicKey -> PublicKey
    PublicKey getPublicKeyFromKeySpec(String base64PublicKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedBase64PubKey = Base64.getDecoder().decode(base64PublicKey);

        return KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(decodedBase64PubKey));
    }

    // base64PrivateKey -> PrivateKey
    PrivateKey getPrivateKeyFromKeySpec(String base64PrivateKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] decodedBase64PrivateKey = Base64.getDecoder().decode(base64PrivateKey);

        return KeyFactory.getInstance("RSA")
            .generatePrivate(new PKCS8EncodedKeySpec(decodedBase64PrivateKey));
    }
}
