package com.github.zhenwei.core.crypto.params;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.GOST3410Parameters;

public class GOST3410KeyParameters
        extends AsymmetricKeyParameter
{
    private GOST3410Parameters    params;

    public GOST3410KeyParameters(
        boolean         isPrivate,
        GOST3410Parameters   params)
    {
        super(isPrivate);

        this.params = params;
    }

    public GOST3410Parameters getParameters()
    {
        return params;
    }
}