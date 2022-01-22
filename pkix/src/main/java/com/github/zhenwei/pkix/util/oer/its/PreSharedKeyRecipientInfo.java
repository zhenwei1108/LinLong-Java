package com.github.zhenwei.pkix.util.oer.its;


import com.github.zhenwei.core.asn1.ASN1OctetString;

/**
 * PreSharedKeyRecipientInfo ::= HashedId8
 */
public class PreSharedKeyRecipientInfo
    extends HashedId
{
    public PreSharedKeyRecipientInfo(byte[] string)
    {
        super(string);
    }

    public static PreSharedKeyRecipientInfo getInstance(Object object)
    {
        if (object instanceof PreSharedKeyRecipientInfo)
        {
            return (PreSharedKeyRecipientInfo)object;
        }
        ASN1OctetString octetString = ASN1OctetString.getInstance(object);
        return new PreSharedKeyRecipientInfo(octetString.getOctets());
    }
}