package com.github.zhenwei.pkix.util.asn1.smime;


import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERSet;

public class SMIMECapabilitiesAttribute
    extends Attribute
{
    public SMIMECapabilitiesAttribute(
        SMIMECapabilityVector capabilities)
    {
        super(SMIMEAttributes.smimeCapabilities,
                new DERSet(new DERSequence(capabilities.toASN1EncodableVector())));
    }
}