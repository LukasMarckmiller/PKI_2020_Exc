package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils;/*
 * (C) 2017, Lukas, l.marckmiller@hm.edu on 20.05.2020.
 * Java 1.8.0_121, Windows 10 Pro 64bit
 * Intel Core i5-6600K CPU/3.50GHz overclocked 4.1GHz, 4 cores, 16000 MByte RAM)
 * with IntelliJ IDEA 2017.1.1
 *
 */

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CryptoUtils {

    public static String base64Encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] base64Decode(String decodedString) {
        return Base64.getDecoder().decode(decodedString);
    }

    public static byte[] hash(String messageDigestName, String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(messageDigestName);
        final byte[] rawHash = digest.digest(message.getBytes(StandardCharsets.UTF_8));

        return rawHash;
    }
}
