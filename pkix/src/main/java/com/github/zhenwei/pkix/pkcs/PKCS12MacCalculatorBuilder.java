package com.github.zhenwei.pkix.pkcs;


import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;

public interface PKCS12MacCalculatorBuilder
{
    MacCalculator build(char[] password)
        throws OperatorCreationException;

    AlgorithmIdentifier getDigestAlgorithmIdentifier();
}