package com.github.zhenwei.provider.jce.spec;

import java.math.BigInteger;
import org.bouncycastle.jce.spec.ElGamalKeySpec;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPublicKeySpec;

/**
 * This class specifies an ElGamal private key with its associated parameters.
 *
 * @see ElGamalPublicKeySpec
 */
public class ElGamalPrivateKeySpec
    extends ElGamalKeySpec
{
    private BigInteger  x;

    public ElGamalPrivateKeySpec(
        BigInteger              x,
        ElGamalParameterSpec    spec)
    {
        super(spec);

        this.x = x;
    }

    /**
     * Returns the private value <code>x</code>.
     *
     * @return the private value <code>x</code>
     */
    public BigInteger getX()
    {
        return x;
    }
}