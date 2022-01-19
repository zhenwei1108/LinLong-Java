package com.github.zhenwei.core.crypto.ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.ec.ECPair;

public interface ECPairTransform
{
    void init(CipherParameters params);

    ECPair transform(ECPair cipherText);
}