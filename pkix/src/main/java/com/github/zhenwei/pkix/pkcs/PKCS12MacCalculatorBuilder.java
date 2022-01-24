package com.github.zhenwei.pkix.pkcs;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import  com.github.zhenwei.pkix.operator.MacCalculator;
import  com.github.zhenwei.pkix.operator.OperatorCreationException;

public interface PKCS12MacCalculatorBuilder
{
    MacCalculator build(char[] password)
        throws OperatorCreationException;

    AlgorithmIdentifier getDigestAlgorithmIdentifier();
}