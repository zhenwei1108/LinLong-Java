package com.github.zhenwei.provider.jce.interfaces;

import java.math.BigInteger;
import javax.crypto.interfaces.DHPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalKey;

public interface ElGamalPrivateKey
    extends ElGamalKey, DHPrivateKey
{
    public BigInteger getX();
}