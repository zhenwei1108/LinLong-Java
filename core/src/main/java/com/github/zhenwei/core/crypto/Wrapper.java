package com.github.zhenwei.core.crypto;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

public interface Wrapper
{
    public void init(boolean forWrapping, CipherParameters param);

    /**
     * Return the name of the algorithm the wrapper implements.
     *
     * @return the name of the algorithm the wrapper implements.
     */
    public String getAlgorithmName();

    public byte[] wrap(byte[] in, int inOff, int inLen);

    public byte[] unwrap(byte[] in, int inOff, int inLen)
        throws InvalidCipherTextException;
}