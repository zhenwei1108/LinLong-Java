package com.github.zhenwei.sdk.util.asn1.cmc;








import java.math.BigInteger;

/**
 * <pre>
 *      id-cmc-getCert OBJECT IDENTIFIER ::= {id-cmc 15}
 *
 *      GetCert ::= SEQUENCE {
 *           issuerName      GeneralName,
 *           serialNumber    INTEGER }
 * </pre>
 */
public class GetCert extends ASN1Object
{
    private final GeneralName issuerName;
    private final BigInteger serialNumber;

    private GetCert(ASN1Sequence seq)
    {
        if (seq.size() != 2)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.issuerName = GeneralName.getInstance(seq.getObjectAt(0));
        this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
    }

    public GetCert(GeneralName issuerName, BigInteger serialNumber)
    {
        this.issuerName = issuerName;
        this.serialNumber = serialNumber;
    }

    public static cmc.GetCert getInstance(Object o)
    {
        if (o instanceof cmc.GetCert)
        {
            return (cmc.GetCert)o;
        }

        if (o != null)
        {
            return new cmc.GetCert(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GeneralName getIssuerName()
    {
        return issuerName;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(issuerName);
        v.add(new ASN1Integer(serialNumber));

        return new DERSequence(v);
    }
}