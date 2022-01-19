package com.github.zhenwei.core.crypto.prng;

import org.bouncycastle.crypto.prng.EntropySource;

public interface EntropySourceProvider
{
    EntropySource get(final int bitsRequired);
}