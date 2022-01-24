package com.github.zhenwei.core.crypto.ec;

import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.math.ec.ECPoint;

public interface ECDecryptor
{
    void init(CipherParameters params);

    ECPoint decrypt(ECPair cipherText);
}