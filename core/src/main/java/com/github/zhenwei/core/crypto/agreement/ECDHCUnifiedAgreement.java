package com.github.zhenwei.core.crypto.agreement;

import ECDHUPrivateParameters;
import ECDHUPublicParameters;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.util.BigIntegers;
import java.math.BigInteger;
 

/**
 * EC Unified static/ephemeral agreement as described in NIST SP 800-56A using EC co-factor Diffie-Hellman.
 */
public class ECDHCUnifiedAgreement
{
    private ECDHUPrivateParameters privParams;

    public void init(
        CipherParameters key)
    {
        this.privParams = (ECDHUPrivateParameters)key;
    }

    public int getFieldSize()
    {
        return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
    }

    public byte[] calculateAgreement(CipherParameters pubKey)
    {
        ECDHUPublicParameters pubParams = (ECDHUPublicParameters)pubKey;

        ECDHCBasicAgreement sAgree = new ECDHCBasicAgreement();
        ECDHCBasicAgreement eAgree = new ECDHCBasicAgreement();

        sAgree.init(privParams.getStaticPrivateKey());

        BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

        eAgree.init(privParams.getEphemeralPrivateKey());

        BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

        int fieldSize = getFieldSize();
        byte[] result = new byte[fieldSize * 2];
        BigIntegers.asUnsignedByteArray(eComp, result, 0, fieldSize);
        BigIntegers.asUnsignedByteArray(sComp, result, fieldSize, fieldSize);
        return result;
    }
}