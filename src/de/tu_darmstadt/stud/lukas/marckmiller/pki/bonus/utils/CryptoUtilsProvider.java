package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils;/*
 * (C) 2017, Lukas, l.marckmiller@hm.edu on 20.05.2020.
 * Java 1.8.0_121, Windows 10 Pro 64bit
 * Intel Core i5-6600K CPU/3.50GHz overclocked 4.1GHz, 4 cores, 16000 MByte RAM)
 * with IntelliJ IDEA 2017.1.1
 *
 */

import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task4.QTESLAPrivateKeyWrapper;
import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task4.QTESLAPublicKeyWrapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CryptoUtilsProvider {

    protected static RSAPrivateKey importRsaPrivateKey(String path) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PEMParser pemParser = new PEMParser(new FileReader(path))) {
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            Object object = pemParser.readObject();
            KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
            return (RSAPrivateKey)kp.getPrivate();
        }
    }

    protected static RSAPublicKey importRsaPublicKey(String path) throws IOException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        try (PemReader pr = new PemReader(new FileReader(path))) {
            EncodedKeySpec spec = new X509EncodedKeySpec(pr.readPemObject().getContent());
            KeyFactory factory = KeyFactory.getInstance("RSA", "BC");
            return (RSAPublicKey)factory.generatePublic(spec);
        }
    }

    protected static String base64Encode(byte[] data){
        return Base64.getEncoder().encodeToString(data);
    }

    protected static byte[] base64Decode(String decodedString) {
        return Base64.getDecoder().decode(decodedString);
    }

    protected static byte[] hash(String messageDigestName, String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(messageDigestName);
        final byte[] rawHash = digest.digest(message.getBytes(StandardCharsets.UTF_8));

        return rawHash;
    }

    protected static byte[] hash(String messageDigestName, byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(messageDigestName);
        final byte[] rawHash = digest.digest(data);

        return rawHash;
    }

    protected static byte[] convertToBytes(Object object) throws IOException {
        try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
             ObjectOutput out = new ObjectOutputStream(bos)) {
            out.writeObject(object);
            return bos.toByteArray();
        }
    }

    protected static Object convertFromBytes(byte[] bytes) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
             ObjectInput in = new ObjectInputStream(bis)) {
            return in.readObject();
        }
    }

    protected static QTESLAPublicKeyParameters importQteslaPublicKey(String path){
        QTESLAPublicKeyWrapper wrapper = new QTESLAPublicKeyWrapper(0,new byte[0]);
        try (BufferedReader reader =new BufferedReader(new FileReader(path))) {
            StringBuilder builder = new StringBuilder();
            reader.lines().forEach(builder::append);
            String qTeslaEncoded = builder.toString();
            wrapper = (QTESLAPublicKeyWrapper) CryptoUtilsProvider.convertFromBytes(CryptoUtilsProvider.base64Decode(qTeslaEncoded));

        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }

        return new QTESLAPublicKeyParameters(wrapper.getSecurityCategory(),wrapper.getPublicData());
    }

    protected static QTESLAPrivateKeyParameters importQteslaPrivateKey(String path){
        QTESLAPrivateKeyWrapper wrapper = new QTESLAPrivateKeyWrapper(0, new byte[0]);
        try (BufferedReader reader =new BufferedReader(new FileReader(path))) {
            StringBuilder builder = new StringBuilder();
            reader.lines().forEach(builder::append);
            String qTeslaEncoded = builder.toString();
            wrapper = (QTESLAPrivateKeyWrapper) CryptoUtilsProvider.convertFromBytes(CryptoUtilsProvider.base64Decode(qTeslaEncoded));
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        return new QTESLAPrivateKeyParameters(wrapper.getSecurityCategory(),wrapper.getSecret());
    }

    protected static X500Name getCAX500Name() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        return x500NameBuilder.addRDN(BCStyle.C,"DE")
                .addRDN(BCStyle.ST, "Hessen")
                .addRDN(BCStyle.L, "Darmstadt")
                .addRDN(BCStyle.O,"CA6 Inc")
                .addRDN(BCStyle.OU,"PKI")
                .addRDN(BCStyle.CN,"CA6").build();
    }
}
