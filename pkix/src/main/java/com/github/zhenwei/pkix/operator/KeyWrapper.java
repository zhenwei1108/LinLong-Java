package com.github.zhenwei.pkix.operator;



public interface KeyWrapper
{
    AlgorithmIdentifier getAlgorithmIdentifier();

    byte[] generateWrappedKey(GenericKey encryptionKey)
        throws OperatorException;
}