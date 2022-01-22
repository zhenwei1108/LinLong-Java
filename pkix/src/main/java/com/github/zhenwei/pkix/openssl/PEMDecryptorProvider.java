package com.github.zhenwei.pkix.openssl;

import org.bouncycastle.operator.OperatorCreationException;

public interface PEMDecryptorProvider
{
    PEMDecryptor get(String dekAlgName)
        throws OperatorCreationException;
}