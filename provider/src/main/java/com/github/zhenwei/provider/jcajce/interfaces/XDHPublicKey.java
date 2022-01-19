package com.github.zhenwei.provider.jcajce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;
import org.bouncycastle.jcajce.interfaces.XDHKey;

public interface XDHPublicKey
    extends XDHKey, PublicKey
{
    BigInteger getU();

    byte[] getUEncoding();
}