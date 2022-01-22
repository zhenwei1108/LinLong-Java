package com.github.zhenwei.core.asn1.pkcs;











public class CertBag
    extends ASN1Object
{
    private ASN1ObjectIdentifier certId;
    private ASN1Encodable certValue;

    private CertBag(
        ASN1Sequence    seq)
    {
        this.certId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        this.certValue = ASN1TaggedObject.getInstance(seq.getObjectAt(1)).getObject();
    }

    public static pkcs.CertBag getInstance(Object o)
    {
        if (o instanceof pkcs.CertBag)
        {
            return (pkcs.CertBag)o;
        }
        else if (o != null)
        {
            return new pkcs.CertBag(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertBag(
        ASN1ObjectIdentifier certId,
        ASN1Encodable        certValue)
    {
        this.certId = certId;
        this.certValue = certValue;
    }

    public ASN1ObjectIdentifier getCertId()
    {
        return certId;
    }

    public ASN1Encodable getCertValue()
    {
        return certValue;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(certId);
        v.add(new DERTaggedObject(0, certValue));

        return new DERSequence(v);
    }
}