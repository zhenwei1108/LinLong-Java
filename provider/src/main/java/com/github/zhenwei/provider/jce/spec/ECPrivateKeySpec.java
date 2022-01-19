package com.github.zhenwei.provider.jce.spec;

import java.math.BigInteger;
import org.bouncycastle.jce.spec.ECKeySpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Elliptic Curve private key specification.
 */
public class ECPrivateKeySpec
    extends ECKeySpec
{
    private BigInteger    d;

    /**
     * base constructor
     *
     * @param d the private number for the key.
     * @param spec the domain parameters for the curve being used.
     */
    public ECPrivateKeySpec(
        BigInteger      d,
        ECParameterSpec spec)
    {
        super(spec);

        this.d = d;
    }

    /**
     * return the private number D
     */
    public BigInteger getD()
    {
        return d;
    }
}