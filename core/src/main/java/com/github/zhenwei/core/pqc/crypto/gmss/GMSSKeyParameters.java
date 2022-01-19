package com.github.zhenwei.core.pqc.crypto.gmss;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.gmss.GMSSParameters;

public class GMSSKeyParameters
    extends AsymmetricKeyParameter
{
    private GMSSParameters params;

    public GMSSKeyParameters(
        boolean isPrivate,
        GMSSParameters params)
    {
        super(isPrivate);
        this.params = params;
    }

    public GMSSParameters getParameters()
    {
        return params;
    }
}