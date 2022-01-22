package com.github.zhenwei.core.crypto;


import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;

public interface KeyEncoder
{
    byte[] getEncoded(AsymmetricKeyParameter keyParameter);
}