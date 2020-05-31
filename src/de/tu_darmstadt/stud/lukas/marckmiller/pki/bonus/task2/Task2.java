package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task2;/*
 * (C) 2017, Lukas, l.marckmiller@hm.edu on 20.05.2020.
 * Java 1.8.0_121, Windows 10 Pro 64bit
 * Intel Core i5-6600K CPU/3.50GHz overclocked 4.1GHz, 4 cores, 16000 MByte RAM)
 * with IntelliJ IDEA 2017.1.1
 *
 */

import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils.CryptoUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class Task2 {
    static final String dataToSignPath = "C:\\Users\\Lukas\\OneDrive\\Dokumente\\TU\\PKI\\Enc_E6.txt";
    static final String privateKeyPath = "C:\\Users\\Lukas\\OneDrive\\Dokumente\\TU\\PKI\\private.pem";

    private RSAPublicKey importPublicKey(String path) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PemReader pr = new PemReader(new FileReader(path))) {
            EncodedKeySpec spec = new X509EncodedKeySpec(pr.readPemObject().getContent());
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            return (RSAPublicKey)factory.generatePublic(spec);
        }
    }

    private RSAPrivateKey importPrivateKey(String path) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PEMParser pemParser = new PEMParser(new FileReader(path))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object object = pemParser.readObject();
            KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
            return (RSAPrivateKey)kp.getPrivate();
        }
    }

    private byte[] SignWithSha256Rsa(byte[] data, RSAPrivateKey rsaPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance("SHA256WithRSA");
        sig.initSign(rsaPrivateKey);
        sig.update(data);
        byte[] signedData = sig.sign();
        return signedData;
    }

    public void mainTask() throws IOException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, SignatureException, InvalidKeyException {
        byte[] data = null;
        String decodedData = null;

        var key = importPrivateKey(privateKeyPath);
        try(var br = new BufferedReader(new FileReader(dataToSignPath, Charset.defaultCharset()))){
            StringBuilder builder = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null){
                builder.append(line);
            }
            decodedData = builder.toString();
        }

        data = CryptoUtils.base64Decode(decodedData);

        byte[] sig = SignWithSha256Rsa(data,key);
        String encodedSig = CryptoUtils.base64Encode(sig);
        System.out.println(encodedSig);
    }
}
