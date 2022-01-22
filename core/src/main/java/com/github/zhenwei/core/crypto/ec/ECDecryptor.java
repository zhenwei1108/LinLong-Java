package com.github.zhenwei.core.crypto.ec;


import com.github.zhenwei.core.crypto.CipherParameters;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}