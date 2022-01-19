package com.github.zhenwei.core.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.ElGamalKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;

public class ElGamalPublicKeyParameters
    extends ElGamalKeyParameters
{
    private BigInteger      y;

    public ElGamalPublicKeyParameters(
        BigInteger      y,
        ElGamalParameters    params)
    {
        super(false, params);

        this.y = y;
    }   

    public BigInteger getY()
    {
        return y;
    }

    public int hashCode()
    {
        return y.hashCode() ^ super.hashCode();
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof org.bouncycastle.crypto.params.ElGamalPublicKeyParameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.ElGamalPublicKeyParameters other = (org.bouncycastle.crypto.params.ElGamalPublicKeyParameters)obj;

        return other.getY().equals(y) && super.equals(obj);
    }
}