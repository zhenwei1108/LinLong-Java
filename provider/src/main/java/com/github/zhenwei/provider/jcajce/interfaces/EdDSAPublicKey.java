package com.github.zhenwei.provider.jcajce.interfaces;

import java.security.PublicKey;

public interface EdDSAPublicKey
    extends EdDSAKey, PublicKey
{
    byte[] getPointEncoding();
}