package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task4;

import org.bouncycastle.pqc.crypto.qtesla.QTESLAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;

import java.io.Serializable;

public class QTESLAPrivateKeyExportWrapper implements Serializable {
    private final byte[] secret;
    private final int securityCategory;

    public QTESLAPrivateKeyExportWrapper(QTESLAPrivateKeyParameters privateKey){
        this.secret = privateKey.getSecret();
        this.securityCategory = privateKey.getSecurityCategory();
    }

    public QTESLAPrivateKeyExportWrapper(int securityCategory, byte[] secret){
        this.secret = secret;
        this.securityCategory = securityCategory;
    }

    public byte[] getSecret() {
        return secret;
    }

    public int getSecurityCategory() {
        return securityCategory;
    }
}
