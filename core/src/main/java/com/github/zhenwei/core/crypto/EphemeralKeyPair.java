package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyEncoder;

public class EphemeralKeyPair
{
    private AsymmetricCipherKeyPair keyPair;
    private KeyEncoder publicKeyEncoder;

    public EphemeralKeyPair(AsymmetricCipherKeyPair keyPair, KeyEncoder publicKeyEncoder)
    {
        this.keyPair = keyPair;
        this.publicKeyEncoder = publicKeyEncoder;
    }

    public AsymmetricCipherKeyPair getKeyPair()
    {
        return keyPair;
    }

    public byte[] getEncodedPublicKey()
    {
        return publicKeyEncoder.getEncoded(keyPair.getPublic());
    }
}