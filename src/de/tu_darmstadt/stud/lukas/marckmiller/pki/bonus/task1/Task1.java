package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task1;/*
 * (C) 2017, Lukas, l.marckmiller@hm.edu on 29.04.2020.
 * Java 1.8.0_121, Windows 10 Pro 64bit
 * Intel Core i5-6600K CPU/3.50GHz overclocked 4.1GHz, 4 cores, 16000 MByte RAM)
 * with IntelliJ IDEA 2017.1.1
 *
 */

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Task1 {
    static final String PUB_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAu95NwlIz3WBgtCnL6Y4N\n" +
            "VWQOn/x0VC63nJ6gvXdQ5/j6d9Qxo9DqxIYqATnmfXs5VMmzFPeWi3hTWx4MCCn9\n" +
            "gj/iHG40mVtk20qC7SqUAriQk1yECTPh3tDcXZ8Im6VD7crSJzX9MbK1JZs59vRl\n" +
            "zUYv0fnhW4YDEddtRhzxXRCPxAsDOH9GFzky/m02Kr1JNtFxMLtTAFnRym0OSHwo\n" +
            "2yHpOyt2wGg9eRWn3agtTOPZAlKTXW18VI+Te5bo1jOBFjCi+twLPz37+TVG3QrR\n" +
            "JSXjbVUhBKjzEL42l3wPlqM/AH4lRO8vdgXwMYl7qPgfhq8bIc6FZczB8WJ0l93s\n" +
            "R7wekwdTfxQaA0we/ZTlH36+eIfSKjj6+V17VLFaFNSt9TmouSf7W3plnouIOR6P\n" +
            "C2BR41DL1vApPeFWCgUEbeOcTXrg1UiMhV80gfCLPfXn7pOc4INFeK9MP+OILzRw\n" +
            "L9+5bs6jBQxXwBDUy2wqiHDzJ/L2f0cyFGz5XczWZq+CU7Wp5SkuuVx1XI3N92LC\n" +
            "53t4HG1jRy+CL0VIymP6XTQhXv5FJMjH4uMCxjD5rLlK6OA+PmhKe1qSrgvhF/tb\n" +
            "4FAP+P9+Svp54SJ64pCmxG5BxBmuz3VeJ0fPZ23O3ap+G1abI7xQRYCcVz6FTYut\n" +
            "8OcU/nwLx97G0XH5NxwVVLECAwEAAQ==\n" +
            "-----END PUBLIC KEY-----\n";
    static final String s = "Lukas Marckmiller;lukas.marckmiller@stud.tu-darmstadt.de;2952923";

    private byte[] hash(String messageDigestName, String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(messageDigestName);
        final byte[] rawHash = digest.digest(message.getBytes(StandardCharsets.UTF_8));

        return rawHash;
    }

    private String base64Encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] encryptRsaPkcs1Ecb(String data, RSAPublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidCipherTextException {
        AsymmetricBlockCipher rsaEngine = new PKCS1Encoding(new RSAEngine());
        rsaEngine.init(true,new RSAKeyParameters(false,publicKey.getModulus(),publicKey.getPublicExponent()));
        byte[] rawData = data.getBytes(StandardCharsets.UTF_8);
        byte[] encData = rsaEngine.processBlock(rawData,0,rawData.length);
        return encData;
    }

    private RSAPublicKey readPublicX509RSAKey(String pk) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        PemReader pr = new PemReader(new StringReader(pk));
        PemObject pemObject = pr.readPemObject();
        EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(pemObject.getContent());
        KeyFactory factory = KeyFactory.getInstance("RSA","BC");
        return (RSAPublicKey)factory.generatePublic(encodedKeySpec);
    }

    private RSAPublicKey importPublicKey(String path) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PemReader pr = new PemReader(new FileReader(path))) {
            EncodedKeySpec spec = new X509EncodedKeySpec(pr.readPemObject().getContent());
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            return (RSAPublicKey)factory.generatePublic(spec);
        }
    }

    private RSAPrivateKey importPrivateKey(String path) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PemReader pr = new PemReader(new FileReader(path))) {
            EncodedKeySpec spec = new X509EncodedKeySpec(pr.readPemObject().getContent());
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            return (RSAPrivateKey) factory.generatePublic(spec);
        }
    }

    public void mainTask1() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, InvalidCipherTextException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] hash = null;
        try {
            hash = hash("SHA-256",s);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        String encodedHash = base64Encode(hash);
        String payload = String.format("%s;%s",s,encodedHash);
        System.out.println(payload);

        RSAPublicKey pk = readPublicX509RSAKey(PUB_KEY);
        String encodedEncryptedData = base64Encode(encryptRsaPkcs1Ecb(payload,pk));
        System.out.println(encodedEncryptedData);
    }
}
