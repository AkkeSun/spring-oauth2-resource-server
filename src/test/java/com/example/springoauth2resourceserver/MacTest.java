package com.example.springoauth2resourceserver;

import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

public class MacTest {

    @Test
    void test() throws Exception {
        String secretKey = "myKey";
        String data = "hello World";
        hmacBase64(secretKey, data, "HmacMD5");
        hmacBase64(secretKey, data, "HmacSHA256");
    }

    void hmacBase64(String secret, String data, String algorithms) throws Exception {

        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes("utf-8"), algorithms);
        Mac mac = Mac.getInstance(algorithms);
        mac.init(secretKey);
        byte[] hash = mac.doFinal(data.getBytes());

        String encodedStr = Base64.getEncoder().encodeToString(hash);
        System.out.println(algorithms + ": " + encodedStr);
    }
}
