package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task3;

import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils.CryptoUtilsProvider;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.tls.ExtensionType;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import javax.security.auth.x500.X500Principal;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Calendar;
import java.util.Date;

public class Task3 extends CryptoUtilsProvider {
    private static final String publicKeyPath = "/home/lukas/Dokumente/tu/pki/PubKey_E6.pem";
    private static final String privateKeyPath = "/home/lukas/Dokumente/tu/pki/private.pem";
    private static final String signatureAlgorithm = "SHA256WithRSA";

    public void mainTask() {
        try {
            var cert = generateX509Cert();
            try(PemWriter writer = new PemWriter(new FileWriter("cert.crt"))) {
                PemObjectGenerator objectGenerator = new JcaMiscPEMGenerator(cert);
                writer.writeObject(objectGenerator);
            }
        } catch (NoSuchAlgorithmException |
                NoSuchProviderException |
                InvalidKeySpecException |
                IOException |
                OperatorCreationException e) {
            e.printStackTrace();
        }
    }

    private X509CertificateHolder generateX509Cert() throws
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

        Date now = new Date(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.YEAR,1);

        JcaX509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                x500NameBuilder.build(),
                new BigInteger(String.valueOf(System.currentTimeMillis())),
                now,
                calendar.getTime(),x500NameBuilder.build(),
                importRsaPublicKey(publicKeyPath));

        certificateBuilder.addExtension(Extension.basicConstraints,false,new BasicConstraints(false));
        certificateBuilder.addExtension(Extension.issuerAlternativeName,false,new GeneralNames(new GeneralName(GeneralName.rfc822Name, "fDqi5sU062iLUOLfW+IcR27ASASEipF75YkCBEaZge8=")));
        certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        var signer = new JcaContentSignerBuilder(signatureAlgorithm).build(importRsaPrivateKey(privateKeyPath));
        return certificateBuilder.build(signer);
    }
}
