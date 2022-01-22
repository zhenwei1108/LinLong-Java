package com.github.zhenwei.sdk.util.asn1.crmf;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.GeneralName;
import java.math.BigInteger;

public class CertId
    extends ASN1Object
{
    private GeneralName issuer;
    private ASN1Integer serialNumber;

    private CertId(ASN1Sequence seq)
    {
        issuer = GeneralName.getInstance(seq.getObjectAt(0));
        serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public static crmf.CertId getInstance(Object o)
    {
        if (o instanceof crmf.CertId)
        {
            return (crmf.CertId)o;
        }

        if (o != null)
        {
            return new crmf.CertId(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public static crmf.CertId getInstance(ASN1TaggedObject obj, boolean isExplicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    public CertId(GeneralName issuer, BigInteger serialNumber)
    {
        this(issuer, new ASN1Integer(serialNumber));
    }

    public CertId(GeneralName issuer, ASN1Integer serialNumber)
    {
        this.issuer = issuer;
        this.serialNumber = serialNumber;
    }

    public GeneralName getIssuer()
    {
        return issuer;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    /**
     * <pre>
     * CertId ::= SEQUENCE {
     *                 issuer           GeneralName,
     *                 serialNumber     INTEGER }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(issuer);
        v.add(serialNumber);
        
        return new DERSequence(v);
    }
}