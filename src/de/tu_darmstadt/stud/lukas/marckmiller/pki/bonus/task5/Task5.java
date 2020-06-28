package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task5;/*
 * (C) 2017, Lukas, l.marckmiller@hm.edu on 28.06.2020.
 * Java 1.8.0_121, Windows 10 Pro 64bit
 * Intel Core i5-6600K CPU/3.50GHz overclocked 4.1GHz, 4 cores, 16000 MByte RAM)
 * with IntelliJ IDEA 2017.1.1
 *
 */

import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils.CryptoUtilsProvider;
import org.bouncycastle.asn1.bc.SignatureCheck;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jcajce.provider.asymmetric.x509.VerifyHelper;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.HybridCSRBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAContentSigner;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileWriter;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;

public class Task5 extends CryptoUtilsProvider {

    private final String CAPublicKeyPath = "/home/lukas/Dokumente/tu/pki/ca/caPub.pem";
    private final String CAPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/ca/ca.pem";
    private final String CAQteslaPublicKeyPath = "/home/lukas/Dokumente/tu/pki/1.qteslaPub";
    private final String CAQteslaPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/1.qtesla";
    private static final String signatureAlgorithm = "SHA256WithRSA";

    public void mainTask() {
        PKCS10CertificationRequest pkcs10CertificationRequest = null;
        try {
            pkcs10CertificationRequest = generateX509HybridCACSR();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException | IOException | OperatorCreationException e) {
            e.printStackTrace();
        }
        try(PemWriter writer = new PemWriter(new FileWriter("CA6.csr"))) {
            PemObjectGenerator objectGenerator = new JcaMiscPEMGenerator(pkcs10CertificationRequest);
            writer.writeObject(objectGenerator);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private PKCS10CertificationRequest generateX509HybridCACSR() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException, OperatorCreationException {
        X500Name x500Name = getCAX500Name();

        Date now = new Date(System.currentTimeMillis());
        Calendar notBefore = Calendar.getInstance();
        notBefore.setTime(now);
        notBefore.add(Calendar.MONTH,-1);
        Calendar notAfter = Calendar.getInstance();
        notAfter.setTime(now);
        notAfter.add(Calendar.MONTH,2);
        RSAPublicKey publicKey = importRsaPublicKey(CAPublicKeyPath);
        HybridCSRBuilder builder = new HybridCSRBuilder(
                x500Name,
                publicKey,
                importQteslaPublicKey(CAQteslaPublicKeyPath)
        );

        builder.addExtension(Extension.subjectKeyIdentifier,false,
                new SubjectKeyIdentifier(hash("SHA-1",
                        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()).getPublicKeyData().getBytes())));

        var signerPrimary = new JcaContentSignerBuilder(signatureAlgorithm).build(importRsaPrivateKey(CAPrivateKeyPath));
        var signerSecondary = new QTESLAContentSigner(importQteslaPrivateKey(CAQteslaPrivateKeyPath));
        return builder.buildHybrid(signerPrimary,signerSecondary);
    }
}