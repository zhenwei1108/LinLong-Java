package com.github.zhenwei.provider.jcajce.provider.symmetric.util;

import org.bouncycastle.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}