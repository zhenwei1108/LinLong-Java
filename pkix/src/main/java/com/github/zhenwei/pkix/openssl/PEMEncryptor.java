package com.github.zhenwei.pkix.openssl;

import org.bouncycastle.openssl.PEMException;

public interface PEMEncryptor
{
    String getAlgorithm();

    byte[] getIV();

    byte[] encrypt(byte[] encoding)
        throws PEMException;
}