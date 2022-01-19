package com.github.zhenwei.core.crypto.params;


import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ElGamalParameters;

public class ElGamalKeyParameters
    extends AsymmetricKeyParameter
{
    private ElGamalParameters    params;

    protected ElGamalKeyParameters(
        boolean         isPrivate,
        ElGamalParameters    params)
    {
        super(isPrivate);

        this.params = params;
    }   

    public ElGamalParameters getParameters()
    {
        return params;
    }

    public int hashCode()
    {
        return (params != null) ? params.hashCode() : 0;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof org.bouncycastle.crypto.params.ElGamalKeyParameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.ElGamalKeyParameters dhKey = (org.bouncycastle.crypto.params.ElGamalKeyParameters)obj;

        if (params == null)
        {
            return dhKey.getParameters() == null;
        }
        else
        { 
            return params.equals(dhKey.getParameters());
        }
    }
}