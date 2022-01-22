package com.github.zhenwei.core.crypto.ec;



public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}