package com.github.zhenwei.sdk.util.oer.its;



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