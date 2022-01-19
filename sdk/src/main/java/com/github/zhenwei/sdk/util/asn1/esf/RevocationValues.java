package com.github.zhenwei.sdk.util.asn1.esf;

import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.esf.OtherRevVals;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x509.CertificateList;

/**
 * <pre>
 * RevocationValues ::= SEQUENCE {
 *    crlVals [0] SEQUENCE OF CertificateList OPTIONAL,
 *    ocspVals [1] SEQUENCE OF BasicOCSPResponse OPTIONAL,
 *    otherRevVals [2] OtherRevVals OPTIONAL}
 * </pre>
 */
public class RevocationValues
    extends ASN1Object
{

    private ASN1Sequence crlVals;
    private ASN1Sequence ocspVals;
    private OtherRevVals otherRevVals;

    public static org.bouncycastle.asn1.esf.RevocationValues getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.RevocationValues)
        {
            return (org.bouncycastle.asn1.esf.RevocationValues)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.esf.RevocationValues(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private RevocationValues(ASN1Sequence seq)
    {
        if (seq.size() > 3)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                + seq.size());
        }
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            ASN1TaggedObject o = (ASN1TaggedObject)e.nextElement();
            switch (o.getTagNo())
            {
                case 0:
                    ASN1Sequence crlValsSeq = (ASN1Sequence)o.getObject();
                    Enumeration crlValsEnum = crlValsSeq.getObjects();
                    while (crlValsEnum.hasMoreElements())
                    {
                        CertificateList.getInstance(crlValsEnum.nextElement());
                    }
                    this.crlVals = crlValsSeq;
                    break;
                case 1:
                    ASN1Sequence ocspValsSeq = (ASN1Sequence)o.getObject();
                    Enumeration ocspValsEnum = ocspValsSeq.getObjects();
                    while (ocspValsEnum.hasMoreElements())
                    {
                        BasicOCSPResponse.getInstance(ocspValsEnum.nextElement());
                    }
                    this.ocspVals = ocspValsSeq;
                    break;
                case 2:
                    this.otherRevVals = OtherRevVals.getInstance(o.getObject());
                    break;
                default:
                    throw new IllegalArgumentException("invalid tag: "
                        + o.getTagNo());
            }
        }
    }

    public RevocationValues(CertificateList[] crlVals,
                            BasicOCSPResponse[] ocspVals, OtherRevVals otherRevVals)
    {
        if (null != crlVals)
        {
            this.crlVals = new DERSequence(crlVals);
        }
        if (null != ocspVals)
        {
            this.ocspVals = new DERSequence(ocspVals);
        }
        this.otherRevVals = otherRevVals;
    }

    public CertificateList[] getCrlVals()
    {
        if (null == this.crlVals)
        {
            return new CertificateList[0];
        }
        CertificateList[] result = new CertificateList[this.crlVals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = CertificateList.getInstance(this.crlVals
                .getObjectAt(idx));
        }
        return result;
    }

    public BasicOCSPResponse[] getOcspVals()
    {
        if (null == this.ocspVals)
        {
            return new BasicOCSPResponse[0];
        }
        BasicOCSPResponse[] result = new BasicOCSPResponse[this.ocspVals.size()];
        for (int idx = 0; idx < result.length; idx++)
        {
            result[idx] = BasicOCSPResponse.getInstance(this.ocspVals
                .getObjectAt(idx));
        }
        return result;
    }

    public OtherRevVals getOtherRevVals()
    {
        return this.otherRevVals;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (null != this.crlVals)
        {
            v.add(new DERTaggedObject(true, 0, this.crlVals));
        }
        if (null != this.ocspVals)
        {
            v.add(new DERTaggedObject(true, 1, this.ocspVals));
        }
        if (null != this.otherRevVals)
        {
            v.add(new DERTaggedObject(true, 2, this.otherRevVals.toASN1Primitive()));
        }
        return new DERSequence(v);
    }
}