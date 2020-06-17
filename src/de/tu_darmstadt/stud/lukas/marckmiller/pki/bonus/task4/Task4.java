package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task4;

import org.bouncycastle.cert.HybridCertificateBuilder;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.qtesla.*;

import java.io.*;
import java.security.SecureRandom;
import de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.utils.CryptoUtilsProvider;

public class Task4 extends CryptoUtilsProvider{
    private QTESLAPublicKeyParameters importQteslaPublicKey(String path){
        QTESLAPublicKeyExportWrapper wrapper = new QTESLAPublicKeyExportWrapper(0,new byte[0]);
        try (BufferedReader reader =new BufferedReader(new FileReader(path))) {
            StringBuilder builder = new StringBuilder();
            reader.lines().forEach(builder::append);
            String qTeslaEncoded = builder.toString();
            wrapper = (QTESLAPublicKeyExportWrapper) CryptoUtilsProvider.convertFromBytes(CryptoUtilsProvider.base64Decode(qTeslaEncoded));

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
                                        new QTESLAPrivateKeyExportWrapper(privKey))));
                pemWriter.flush();

            } catch (IOException e) {
                e.printStackTrace();
            }
            try (FileWriter pemWriter = new FileWriter(outPath + (i+1) + ".qteslaPub")) {
                pemWriter.write(
                        CryptoUtilsProvider.base64Encode(
                                CryptoUtilsProvider.convertToBytes(
                                        new QTESLAPublicKeyExportWrapper(pubKey))));
                pemWriter.flush();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    public void mainTask()  {
        //HybridCertificateBuilder hybridCertificateBuilder = new HybridCertificateBuilder();
        //generateQTeslaKeyPair("/home/lukas/Dokumente/tu/pki/",2);
        QTESLAPublicKeyParameters pubKey = importQteslaPublicKey("/home/lukas/Dokumente/tu/pki/1.qteslaPub");
    }
}

