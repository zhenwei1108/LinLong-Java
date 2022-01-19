package com.github.zhenwei.core.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.ElGamalKeyParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;

public class ElGamalPrivateKeyParameters
    extends ElGamalKeyParameters
{
    private BigInteger      x;

    public ElGamalPrivateKeyParameters(
        BigInteger      x,
        ElGamalParameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters pKey = (org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters)obj;

        if (!pKey.getX().equals(x))
        {
            return false;
        }

        return super.equals(obj);
    }
    
    public int hashCode()
    {
        return getX().hashCode();
    }
}