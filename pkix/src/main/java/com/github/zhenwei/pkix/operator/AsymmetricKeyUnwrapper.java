package com.github.zhenwei.pkix.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.KeyUnwrapper;

public abstract class AsymmetricKeyUnwrapper
    implements KeyUnwrapper
{
    private AlgorithmIdentifier algorithmId;

    protected AsymmetricKeyUnwrapper(AlgorithmIdentifier algorithmId)
    {
        this.algorithmId = algorithmId;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmId;
    }
}