package com.github.zhenwei.core.crypto.ec;


import com.github.zhenwei.core.crypto.CipherParameters;

public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}