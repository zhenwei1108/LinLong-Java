package com.github.zhenwei.provider.jce.spec;

import java.security.spec.KeySpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * base class for an Elliptic Curve Key Spec
 */
public class ECKeySpec
    implements KeySpec
{
    private ECParameterSpec     spec;

    protected ECKeySpec(
        ECParameterSpec spec)
    {
        this.spec = spec;
    }

    /**
     * return the domain parameters for the curve
     */
    public ECParameterSpec getParams()
    {
        return spec;
    }
}