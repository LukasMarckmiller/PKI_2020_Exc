package de.tu_darmstadt.stud.lukas.marckmiller.pki.bonus.task4;

import org.bouncycastle.pqc.crypto.qtesla.QTESLAPublicKeyParameters;

import java.io.Serializable;

public class QTESLAPublicKeyExportWrapper implements Serializable {
    private final byte[] publicData;
    private final int securityCategory;

    public QTESLAPublicKeyExportWrapper(QTESLAPublicKeyParameters pubKey) {
        this.publicData = pubKey.getPublicData();
        this.securityCategory = pubKey.getSecurityCategory();
    }
    public QTESLAPublicKeyExportWrapper(int securityCategory, byte[] publicData) {
        this.publicData = publicData;
        this.securityCategory = securityCategory;
    }
    public int getSecurityCategory() {
        return securityCategory;
    }

    public byte[] getPublicData() {
        return publicData;
    }
}
