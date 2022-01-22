package com.github.zhenwei.core.crypto.ec;

 


public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}