package com.github.zhenwei.pkix.util.asn1.crmf;


import cms.EnvelopedData;
import com.github.zhenwei.core.asn1.ASN1Choice;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERTaggedObject;

public class EncryptedKey
    extends ASN1Object
    implements ASN1Choice
{
    private EnvelopedData envelopedData;
    private EncryptedValue encryptedValue;

    public static crmf.EncryptedKey getInstance(Object o)
    {
        if (o instanceof crmf.EncryptedKey)
        {
            return (crmf.EncryptedKey)o;
        }
        else if (o instanceof ASN1TaggedObject)
        {
            return new crmf.EncryptedKey(EnvelopedData.getInstance((ASN1TaggedObject)o, false));
        }
        else if (o instanceof EncryptedValue)
        {
            return new crmf.EncryptedKey((EncryptedValue)o);
        }
        else
        {
            return new crmf.EncryptedKey(EncryptedValue.getInstance(o));
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