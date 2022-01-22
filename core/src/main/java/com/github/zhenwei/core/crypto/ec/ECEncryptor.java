package com.github.zhenwei.core.crypto.ec;




public interface ECEncryptor
{
    void init(CipherParameters params);

    ECPair encrypt(ECPoint point);
}