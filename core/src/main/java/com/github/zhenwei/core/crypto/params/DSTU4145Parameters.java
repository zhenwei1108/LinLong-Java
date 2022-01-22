package com.github.zhenwei.core.crypto.params;



public class DSTU4145Parameters
    extends ECDomainParameters
{
    private final byte[] dke;

    public DSTU4145Parameters(ECDomainParameters ecParameters, byte[] dke)
    {
        super(ecParameters.getCurve(), ecParameters.getG(), ecParameters.getN(), ecParameters.getH(), ecParameters.getSeed());

        this.dke = Arrays.clone(dke);
    }

    public byte[] getDKE()
    {
        return Arrays.clone(dke);
    }
}