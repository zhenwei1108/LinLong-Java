package com.github.zhenwei.provider.jce.spec;

/**
 * A simple object to indicate that a symmetric cipher should reuse the
 * last key provided.
 * @deprecated use super class  spec.RepeatedSecretKeySpec
 */
public class RepeatedSecretKeySpec
    extends  spec.RepeatedSecretKeySpec
{
    private String algorithm;

    public RepeatedSecretKeySpec(String algorithm)
    {
        super(algorithm);
    }
}