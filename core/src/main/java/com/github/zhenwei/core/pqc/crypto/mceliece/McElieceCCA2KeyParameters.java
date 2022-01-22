package com.github.zhenwei.core.pqc.crypto.mceliece;


import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;

public class McElieceCCA2KeyParameters
    extends AsymmetricKeyParameter
{
    private String params;

    public McElieceCCA2KeyParameters(
        boolean isPrivate,
        String params)
    {
        super(isPrivate);
        this.params = params;
    }


    public String getDigest()
    {
        return params;
    }

}