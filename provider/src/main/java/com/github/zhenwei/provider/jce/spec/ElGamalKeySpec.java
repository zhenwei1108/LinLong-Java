package com.github.zhenwei.provider.jce.spec;

import java.security.spec.KeySpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

public class ElGamalKeySpec
    implements KeySpec
{
    private ElGamalParameterSpec  spec;

    public ElGamalKeySpec(
        ElGamalParameterSpec  spec)
    {
        this.spec = spec;
    }

    public ElGamalParameterSpec getParams()
    {
        return spec;
    }
}