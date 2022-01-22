package com.github.zhenwei.provider.jcajce.provider.symmetric.util;


import com.github.zhenwei.core.crypto.BlockCipher;

public interface BlockCipherProvider
{
    BlockCipher get();
}