package com.github.zhenwei.sdk.util.asn1.crmf;

import org.bouncycastle.asn1.ASN1Integer;

public class SubsequentMessage
    extends ASN1Integer
{
    public static final org.bouncycastle.asn1.crmf.SubsequentMessage encrCert = new org.bouncycastle.asn1.crmf.SubsequentMessage(0);
    public static final org.bouncycastle.asn1.crmf.SubsequentMessage challengeResp = new org.bouncycastle.asn1.crmf.SubsequentMessage(1);
    
    private SubsequentMessage(int value)
    {
        super(value);
    }

    public static org.bouncycastle.asn1.crmf.SubsequentMessage valueOf(int value)
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