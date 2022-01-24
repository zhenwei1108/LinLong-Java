package com.github.zhenwei.provider.jce.spec;

/**
 * A parameter spec for the GOST-28147 cipher.
 * @deprecated use  com.github.zhenwei.provider.jcajce.spec.GOST28147ParameterSpec
 */
public class GOST28147ParameterSpec
    extends com.github.zhenwei.provider.jcajce.spec.GOST28147ParameterSpec
{
    /**
     * @deprecated
     */
    public GOST28147ParameterSpec(
        byte[] sBox)
    {
        super(sBox);
    }

    /**
     * @deprecated
     */
    public GOST28147ParameterSpec(
        byte[] sBox,
        byte[] iv)
    {
        super(sBox, iv);

    }

    /**
     * @deprecated
     */
    public GOST28147ParameterSpec(
        String  sBoxName)
    {
        super(sBoxName);
    }

    /**
     * @deprecated
     */
    public GOST28147ParameterSpec(
        String  sBoxName,
        byte[]  iv)
    {
        super(sBoxName, iv);
    }
}