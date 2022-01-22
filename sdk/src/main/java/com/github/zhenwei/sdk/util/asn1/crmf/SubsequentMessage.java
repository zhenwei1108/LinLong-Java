package com.github.zhenwei.sdk.util.asn1.crmf;



public class SubsequentMessage
    extends ASN1Integer
{
    public static final crmf.SubsequentMessage encrCert = new crmf.SubsequentMessage(0);
    public static final crmf.SubsequentMessage challengeResp = new crmf.SubsequentMessage(1);
    
    private SubsequentMessage(int value)
    {
        super(value);
    }

    public static crmf.SubsequentMessage valueOf(int value)
    {
        if (value == 0)
        {
            return encrCert;
        }
        if (value == 1)
        {
            return challengeResp;
        }

        throw new IllegalArgumentException("unknown value: " + value);
    }
}