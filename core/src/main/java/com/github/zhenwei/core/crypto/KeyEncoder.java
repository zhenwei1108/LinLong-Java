package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public interface KeyEncoder
{
    byte[] getEncoded(AsymmetricKeyParameter keyParameter);
}