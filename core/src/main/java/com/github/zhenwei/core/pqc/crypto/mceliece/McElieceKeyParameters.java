package com.github.zhenwei.core.pqc.crypto.mceliece;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.mceliece.McElieceParameters;


public class McElieceKeyParameters
    extends AsymmetricKeyParameter
{
    private McElieceParameters params;

    public McElieceKeyParameters(
        boolean isPrivate,
        McElieceParameters params)
    {
        super(isPrivate);
        this.params = params;
    }


    public McElieceParameters getParameters()
    {
        return params;
    }

}