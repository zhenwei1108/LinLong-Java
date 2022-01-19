package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PublicKey;
import org.bouncycastle.jcajce.interfaces.EdDSAKey;

public interface EdDSAPublicKey
    extends EdDSAKey, PublicKey
{
    byte[] getPointEncoding();
}