package com.github.zhenwei.provider.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/**
 * ParameterSpec for keys using the LMS Hierarchical Signature System (HSS).
 * @deprecated use LMSKeyGenParameterSpec
 */
public class LMSHSSParameterSpec
    implements AlgorithmParameterSpec
{
    private final LMSParameterSpec[] specs;

    /**
     * Base constructor, specify the LMS parameters at each level of the hierarchy.
     *
     * @param specs the LMS parameter specs for each level of the hierarchy.
     */
    public LMSHSSParameterSpec(LMSParameterSpec[] specs)
    {
        this.specs = specs.clone();
    }

    /**
     * Return the LMS parameters for the HSS hierarchy.
     *
     * @return the HSS component LMS parameter specs.
     */
    public LMSParameterSpec[] getLMSSpecs()
    {
        return specs.clone();
    }
}