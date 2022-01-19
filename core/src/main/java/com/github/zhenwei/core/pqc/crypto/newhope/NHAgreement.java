package com.github.zhenwei.core.pqc.crypto.newhope;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

public class NHAgreement
{
    private NHPrivateKeyParameters privKey;

    public void init(CipherParameters param)
    {
        privKey = (NHPrivateKeyParameters)param;
    }

    public byte[] calculateAgreement(CipherParameters otherPublicKey)
    {
        NHPublicKeyParameters pubKey = (NHPublicKeyParameters)otherPublicKey;

        byte[] sharedValue = new byte[NewHope.AGREEMENT_SIZE];

        NewHope.sharedA(sharedValue, privKey.secData, pubKey.pubData);

        return sharedValue;
    }
}