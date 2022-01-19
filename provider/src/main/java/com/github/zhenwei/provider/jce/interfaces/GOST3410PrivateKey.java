package com.github.zhenwei.provider.jce.interfaces;

import java.math.BigInteger;
import org.bouncycastle.jce.interfaces.GOST3410Key;

public interface GOST3410PrivateKey extends GOST3410Key, java.security.PrivateKey
{

    public BigInteger getX();
}