package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task4;

import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils.CryptoUtilsProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.crypto.qtesla.*;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;

public class Task4 extends CryptoUtilsProvider{
    private final String CAPublicKeyPath = "/home/lukas/Dokumente/tu/pki/ca/caPub.pem";
    private final String CAPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/ca/ca.pem";
    private final String CAQteslaPublicKeyPath = "/home/lukas/Dokumente/tu/pki/1.qteslaPub";
    private final String CAQteslaPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/1.qtesla";
    private final String EEPublicKeyPath = "/home/lukas/Dokumente/tu/pki/ee/eePub.pem";
    private final String EEPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/ee/ee.pem";
    private final String EEQteslaPublicKeyPath = "/home/lukas/Dokumente/tu/pki/2.qteslaPub";
    private final String EEQteslaPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/2.qtesla";
    private static final String signatureAlgorithm = "SHA256WithRSA";

    private X509CertificateHolder generateX509HybridEECertificate(X509CertificateHolder caCert) throws
            NoSuchAlgorithmException,
            NoSuchProviderException,
            InvalidKeySpecException,
            IOException,
            OperatorCreationException {
        var x500NameBuilder = new X500NameBuilder();

        x500NameBuilder.addRDN(BCStyle.C,"DE")
                .addRDN(BCStyle.ST, "Hessen")
                .addRDN(BCStyle.L, "Darmstadt")
                .addRDN(BCStyle.O,"TU Darmstadt")
                .addRDN(BCStyle.OU,"PKI")
                .addRDN(BCStyle.CN,"E6");

        RSAPublicKey publicEEKey= importRsaPublicKey(EEPublicKeyPath);

        Date now = new Date(System.currentTimeMillis());
        Calendar notBefor = Calendar.getInstance();
        notBefor.setTime(now);
        notBefor.add(Calendar.MONTH,-1);
        Calendar notAfter = Calendar.getInstance();
        notAfter.setTime(now);
        notAfter.add(Calendar.MONTH,3);
        HybridCertificateBuilder builder = new HybridCertificateBuilder(
                caCert.getSubject(),
                new BigInteger(String.valueOf(System.currentTimeMillis())),
                notBefor.getTime(),
                notAfter.getTime(),
                x500NameBuilder.build(),
                publicEEKey,
                importQteslaPublicKey(EEQteslaPublicKeyPath));

        builder.addExtension(Extension.authorityKeyIdentifier,false,
                new AuthorityKeyIdentifier(
                        hash("SHA-1", caCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()),
                        new GeneralNames(new GeneralName(GeneralName.directoryName,caCert.getIssuer())),caCert.getSerialNumber()));
        builder.addExtension(Extension.basicConstraints,false,new BasicConstraints(false));
        builder.addExtension(Extension.subjectAlternativeName,false,new GeneralNames(new GeneralName(GeneralName.rfc822Name, "fDqi5sU062iLUOLfW+IcR27ASASEipF75YkCBEaZge8=")));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

        var signerPrimary = new JcaContentSignerBuilder(signatureAlgorithm).build(importRsaPrivateKey(CAPrivateKeyPath));
        var signerSecondary = new QTESLAContentSigner(importQteslaPrivateKey(CAQteslaPrivateKeyPath));
        return builder.buildHybrid(signerPrimary,signerSecondary);
    }

    private X509CertificateHolder generateX509HybridCACertificate() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, OperatorCreationException {
        X500Name x500Name = getCAX500Name();

        Date now = new Date(System.currentTimeMillis());
        Calendar notBefore = Calendar.getInstance();
        notBefore.setTime(now);
        notBefore.add(Calendar.MONTH,-1);
        Calendar notAfter = Calendar.getInstance();
        notAfter.setTime(now);
        notAfter.add(Calendar.MONTH,2);
        RSAPublicKey publicKey = importRsaPublicKey(CAPublicKeyPath);
        var builder = new HybridCertificateBuilder(
                x500Name,
                new BigInteger(String.valueOf(System.currentTimeMillis())),
                notBefore.getTime(),
                notAfter.getTime(),
                x500Name,
                publicKey,
                importQteslaPublicKey(CAQteslaPublicKeyPath)
        );
        builder.addExtension(Extension.subjectKeyIdentifier,false,
                new SubjectKeyIdentifier(hash("SHA-1",
                        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getBytes())));
        builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        var signerPrimary = new JcaContentSignerBuilder(signatureAlgorithm).build(importRsaPrivateKey(CAPrivateKeyPath));
        var signerSecondary = new QTESLAContentSigner(importQteslaPrivateKey(CAQteslaPrivateKeyPath));
        return builder.buildHybrid(signerPrimary,signerSecondary);
    }

    private X500Name getCAX500Name() {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        return x500NameBuilder.addRDN(BCStyle.C,"DE")
                .addRDN(BCStyle.ST, "Hessen")
                .addRDN(BCStyle.L, "Darmstadt")
                .addRDN(BCStyle.O,"CA6 Inc")
                .addRDN(BCStyle.OU,"PKI")
                .addRDN(BCStyle.CN,"CA6").build();
    }

    private QTESLAPrivateKeyParameters importQteslaPrivateKey(String path){
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

    private QTESLAPublicKeyParameters importQteslaPublicKey(String path){
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
    private void generateQTeslaKeyPair(String outPath, int keyCount){
        for (int i = 0; i < keyCount; i++){
            var keyPairGenerator = new QTESLAKeyPairGenerator();
            var qteslaGenParams = new QTESLAKeyGenerationParameters(QTESLASecurityCategory.PROVABLY_SECURE_I,new SecureRandom());
            keyPairGenerator.init(qteslaGenParams);
            AsymmetricCipherKeyPair qTeslaPair = keyPairGenerator.generateKeyPair();
            QTESLAPrivateKeyParameters privKey = (QTESLAPrivateKeyParameters) qTeslaPair.getPrivate();
            QTESLAPublicKeyParameters pubKey = (QTESLAPublicKeyParameters) qTeslaPair.getPublic();

            try (FileWriter pemWriter = new FileWriter(outPath + (i+1) + ".qtesla")) {
                pemWriter.write(
                        CryptoUtilsProvider.base64Encode(
                                CryptoUtilsProvider.convertToBytes(
                                        new QTESLAPrivateKeyWrapper(privKey))));
                pemWriter.flush();

            } catch (IOException e) {
                e.printStackTrace();
            }
            try (FileWriter pemWriter = new FileWriter(outPath + (i+1) + ".qteslaPub")) {
                pemWriter.write(
                        CryptoUtilsProvider.base64Encode(
                                CryptoUtilsProvider.convertToBytes(
                                        new QTESLAPublicKeyWrapper(pubKey))));
                pemWriter.flush();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    public void mainTask()  {
        //generateQTeslaKeyPair("/home/lukas/Dokumente/tu/pki/",2);
        X509CertificateHolder caCert = null;
        try {
            caCert = generateX509HybridCACertificate();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | IOException | OperatorCreationException e) {
            e.printStackTrace();
        }
        try(PemWriter writer = new PemWriter(new FileWriter("CAcert_CA6.crt"))) {
            PemObjectGenerator objectGenerator = new JcaMiscPEMGenerator(caCert);
            writer.writeObject(objectGenerator);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try(PemWriter writer = new PemWriter(new FileWriter("EEcert_E6.crt"))) {
            PemObjectGenerator objectGenerator = new JcaMiscPEMGenerator(generateX509HybridEECertificate(caCert));
            writer.writeObject(objectGenerator);
        } catch (IOException | InvalidKeySpecException | OperatorCreationException | NoSuchProviderException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

