package com.github.zhenwei.sdk.util.asn1.crmf;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.EncryptedValue;

public class EncryptedKey
    extends ASN1Object
    implements ASN1Choice
{
    private EnvelopedData envelopedData;
    private EncryptedValue encryptedValue;

    public static org.bouncycastle.asn1.crmf.EncryptedKey getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.asn1.crmf.EncryptedKey)
        {
            return (org.bouncycastle.asn1.crmf.EncryptedKey)o;
        }
        else if (o instanceof ASN1TaggedObject)
        {
            return new org.bouncycastle.asn1.crmf.EncryptedKey(EnvelopedData.getInstance((ASN1TaggedObject)o, false));
        }
        else if (o instanceof EncryptedValue)
        {
            return new org.bouncycastle.asn1.crmf.EncryptedKey((EncryptedValue)o);
        }
        else
        {
            return new org.bouncycastle.asn1.crmf.EncryptedKey(EncryptedValue.getInstance(o));
        }
    }

    public EncryptedKey(EnvelopedData envelopedData)
    {
        this.envelopedData = envelopedData;
    }

    public EncryptedKey(EncryptedValue encryptedValue)
    {
        this.encryptedValue = encryptedValue;
    }

    public boolean isEncryptedValue()
    {
        return encryptedValue != null;
    }

    public ASN1Encodable getValue()
    {
        if (encryptedValue != null)
        {
            return encryptedValue;
        }

        return envelopedData;
    }

    /**
     * <pre>
     *    EncryptedKey ::= CHOICE {
     *        encryptedValue        EncryptedValue, -- deprecated
     *        envelopedData     [0] EnvelopedData }
     *        -- The encrypted private key MUST be placed in the envelopedData
     *        -- encryptedContentInfo encryptedContent OCTET STRING.
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (encryptedValue != null)
        {
            return encryptedValue.toASN1Primitive();
        }

        return new DERTaggedObject(false, 0, envelopedData);
    }
}