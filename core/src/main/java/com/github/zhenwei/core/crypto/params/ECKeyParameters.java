package com.github.zhenwei.core.crypto.params;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;

public class ECKeyParameters
    extends AsymmetricKeyParameter
{
    private final ECDomainParameters parameters;

    protected ECKeyParameters(
        boolean             isPrivate,
        ECDomainParameters  parameters)
    {
        super(isPrivate);

        if (null == parameters)
        {
            throw new NullPointerException("'parameters' cannot be null");
        }

        this.parameters = parameters;
    }

    public ECDomainParameters getParameters()
    {
        return parameters;
    }
}