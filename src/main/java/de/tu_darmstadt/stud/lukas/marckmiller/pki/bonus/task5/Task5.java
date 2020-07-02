package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task5;/*
 * (C) 2017, Lukas, l.marckmiller@hm.edu on 28.06.2020.
 * Java 1.8.0_121, Windows 10 Pro 64bit
 * Intel Core i5-6600K CPU/3.50GHz overclocked 4.1GHz, 4 cores, 16000 MByte RAM)
 * with IntelliJ IDEA 2017.1.1
 *
 */

import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils.CryptoUtilsProvider;
import org.apache.commons.io.FilenameUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.HybridCertUtils;
import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.jce.provider.HybridValidation;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.HybridCSRBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAContentSigner;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAUtils;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;

public class Task5 extends CryptoUtilsProvider {

    private static final String CAPublicKeyPath = "/home/lukas/Dokumente/tu/pki/ca/caPub.pem";
    private static final String CAPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/ca/ca.pem";
    private static final String CAQteslaPublicKeyPath = "/home/lukas/Dokumente/tu/pki/1.qteslaPub";
    private static final String CAQteslaPrivateKeyPath = "/home/lukas/Dokumente/tu/pki/1.qtesla";
    private static final String signatureAlgorithm = "SHA256WithRSA";
    private static final String importedCsrName = "/home/lukas/IdeaProjects/PKI_2020_Exc/CA85.csr";
    private static final String CACert = "/home/lukas/IdeaProjects/PKI_2020_Exc/CA35-CA6.crt";


    public void mainTask()  {
        //subTask1();

        X509CertificateHolder caCert = null;
        try (PEMParser reader = new PEMParser(new PemReader(new FileReader(CACert)))){
            caCert = (X509CertificateHolder)reader.readObject();
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (caCert == null) {
            System.err.println("CA Certificate for signing the Certificate Signing Request not found. " + CACert);
            return;
        }

        X509CertificateHolder certificate = ValidateAndSignHybridCsr(caCert);

        if (certificate == null) {
            System.err.println("Invalid signature for Certificate Signing Request.");
            return;
        }
        String outFileName = "CA6-" + FilenameUtils.getBaseName(Paths.get(importedCsrName).getFileName().toString());
        try (PemWriter pemWriter = new PemWriter(new FileWriter(outFileName + ".crt"))) {
            pemWriter.writeObject(new JcaMiscPEMGenerator(certificate));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private X509CertificateHolder ValidateAndSignHybridCsr( X509CertificateHolder caSignerCert) {
        try (PEMParser reader = new PEMParser(new PemReader(new FileReader(importedCsrName)))){
            PKCS10CertificationRequest pkcs10Request = (PKCS10CertificationRequest) reader.readObject();
            JcaX509ContentVerifierProviderBuilder contentVerifierBuilder = new JcaX509ContentVerifierProviderBuilder();
            boolean isValid = pkcs10Request.isSignatureValid(contentVerifierBuilder.build(pkcs10Request.getSubjectPublicKeyInfo()));
            if (isValid){
                X500Name x500Name = getCAX500Name();

                Date now = new Date(System.currentTimeMillis());
                Calendar notBefore = Calendar.getInstance();
                notBefore.setTime(now);
                notBefore.add(Calendar.MONTH,-1);
                Calendar notAfter = Calendar.getInstance();
                notAfter.setTime(now);
                notAfter.add(Calendar.MONTH,2);

                var builder = new HybridCertificateBuilder(
                        x500Name,
                        new BigInteger(String.valueOf(System.currentTimeMillis())),
                        notBefore.getTime(),
                        notAfter.getTime(),
                        pkcs10Request.getSubject(),
                        pkcs10Request.getSubjectPublicKeyInfo(),
                        QTESLAUtils.fromSubjectPublicKeyInfo(HybridKey.fromCSR(pkcs10Request).getKey())
                );
                builder.addExtension(Extension.subjectKeyIdentifier,false,
                        new SubjectKeyIdentifier(hash("SHA-1",
                                pkcs10Request.getSubjectPublicKeyInfo().getPublicKeyData().getBytes())));
                builder.addExtension(Extension.authorityKeyIdentifier,false,
                        new AuthorityKeyIdentifier(
                                hash("SHA-1", caSignerCert.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()),
                                new GeneralNames(new GeneralName(GeneralName.directoryName,caSignerCert.getSubject())),caSignerCert.getSerialNumber()));
                builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(true));
                builder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

                var signerPrimary = new JcaContentSignerBuilder(signatureAlgorithm).build(importRsaPrivateKey(CAPrivateKeyPath));
                var signerSecondary = new QTESLAContentSigner(importQteslaPrivateKey(CAQteslaPrivateKeyPath));
                return builder.buildHybrid(signerPrimary,signerSecondary);
            }

        } catch (IOException | PKCSException | OperatorCreationException | NoSuchProviderException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void subTask1() {
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