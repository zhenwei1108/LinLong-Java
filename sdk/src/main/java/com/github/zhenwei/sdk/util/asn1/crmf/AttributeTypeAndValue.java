package com.github.zhenwei.sdk.util.asn1.crmf;









public class AttributeTypeAndValue
    extends ASN1Object
{
    private ASN1ObjectIdentifier type;
    private ASN1Encodable       value;

    private AttributeTypeAndValue(ASN1Sequence seq)
    {
        type = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        value = (ASN1Encodable)seq.getObjectAt(1);
    }

    public static crmf.AttributeTypeAndValue getInstance(Object o)
    {
        if (o instanceof crmf.AttributeTypeAndValue)
        {
            return (crmf.AttributeTypeAndValue)o;
        }

        if (o != null)
        {
            return new crmf.AttributeTypeAndValue(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AttributeTypeAndValue(
        String oid,
        ASN1Encodable value)
    {
        this(new ASN1ObjectIdentifier(oid), value);
    }

    public AttributeTypeAndValue(
        ASN1ObjectIdentifier type,
        ASN1Encodable value)
    {
        this.type = type;
        this.value = value;
    }

    public ASN1ObjectIdentifier getType()
    {
        return type;
    }

    public ASN1Encodable getValue()
    {
        return value;
    }

    /**
     * <pre>
     * AttributeTypeAndValue ::= SEQUENCE {
     *           type         OBJECT IDENTIFIER,
     *           value        ANY DEFINED BY type }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(type);
        v.add(value);

        return new DERSequence(v);
    }
}