package com.github.zhenwei.sdk.util.asn1.tsp;








/**
 * Implementation of the CryptoInfos element defined in RFC 4998:
 * <p>
 * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
 */
public class CryptoInfos
    extends ASN1Object
{
    private ASN1Sequence attributes;

    public static tsp.CryptoInfos getInstance(final Object obj)
    {
        if (obj instanceof tsp.CryptoInfos)
        {
            return (tsp.CryptoInfos)obj;
        }
        else if (obj != null)
        {
            return new tsp.CryptoInfos(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static tsp.CryptoInfos getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private CryptoInfos(final ASN1Sequence attributes)
    {
        this.attributes = attributes;
    }

    public CryptoInfos(Attribute[] attrs)
    {
        attributes = new DERSequence(attrs);
    }

    public Attribute[] getAttributes()
    {
        Attribute[] rv = new Attribute[attributes.size()];

        for (int i = 0; i != rv.length; i++)
        {
            rv[i] = Attribute.getInstance(attributes.getObjectAt(i));
        }

        return rv;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return attributes;
    }
}