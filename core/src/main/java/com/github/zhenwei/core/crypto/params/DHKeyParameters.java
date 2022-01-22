package com.github.zhenwei.core.crypto.params;


 
 

public class DHKeyParameters
    extends AsymmetricKeyParameter
{
    private DHParameters    params;

    protected DHKeyParameters(
        boolean         isPrivate,
        DHParameters    params)
    {
        super(isPrivate);

        this.params = params;
    }   

    public DHParameters getParameters()
    {
        return params;
    }

    public boolean equals(
        Object  obj)
    {
        if (!(obj instanceof org.bouncycastle.crypto.params.DHKeyParameters))
        {
            return false;
        }

        org.bouncycastle.crypto.params.DHKeyParameters dhKey = (org.bouncycastle.crypto.params.DHKeyParameters)obj;

        if (params == null)
        {
            return dhKey.getParameters() == null;
        }
        else
        { 
            return params.equals(dhKey.getParameters());
        }
    }
    
    public int hashCode()
    {
        int code = isPrivate() ? 0 : 1;
        
        if (params != null)
        {
            code ^= params.hashCode();
        }
        
        return code;
    }
}