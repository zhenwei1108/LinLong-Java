package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;

/**
 * base interface for general purpose byte derivation functions.
 */
public interface DerivationFunction
{
    public void init(DerivationParameters param);

    public int generateBytes(byte[] out, int outOff, int len)
        throws DataLengthException, IllegalArgumentException;
}