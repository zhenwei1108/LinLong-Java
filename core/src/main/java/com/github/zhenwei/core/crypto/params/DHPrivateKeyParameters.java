package com.github.zhenwei.core.crypto.params;

import java.math.BigInteger;
 

public class DHPrivateKeyParameters
    extends DHKeyParameters
{
    private BigInteger      x;

    public DHPrivateKeyParameters(
        BigInteger      x,
        DHParameters    params)
    {
        super(true, params);

        this.x = x;
    }   

    public BigInteger getX()
    {
        return x;
    }

    public int hashCode()
    {
        return x.hashCode() ^ super.hashCode();
    }
    
    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof org.bouncycastle.crypto.params.DHPrivateKeyParameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.DHPrivateKeyParameters other = (org.bouncycastle.crypto.params.DHPrivateKeyParameters)obj;

        return other.getX().equals(this.x) && super.equals(obj);
    }
}