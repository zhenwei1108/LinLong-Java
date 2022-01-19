package com.github.zhenwei.core.asn1.x509;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;

public class AttributeCertificate
    extends ASN1Object
{
    AttributeCertificateInfo    acinfo;
    AlgorithmIdentifier         signatureAlgorithm;
    DERBitString                signatureValue;

    /**
     * @param obj
     * @return an AttributeCertificate object
     */
    public static org.bouncycastle.asn1.x509.AttributeCertificate getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.x509.AttributeCertificate)
        {
            return (org.bouncycastle.asn1.x509.AttributeCertificate)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.x509.AttributeCertificate(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public AttributeCertificate(
        AttributeCertificateInfo    acinfo,
        AlgorithmIdentifier         signatureAlgorithm,
        DERBitString                signatureValue)
    {
        this.acinfo = acinfo;
        this.signatureAlgorithm = signatureAlgorithm;
        this.signatureValue = signatureValue;
    }

    private AttributeCertificate(
        ASN1Sequence    seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        this.acinfo = AttributeCertificateInfo.getInstance(seq.getObjectAt(0));
        this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.signatureValue = DERBitString.getInstance(seq.getObjectAt(2));
    }
    
    public AttributeCertificateInfo getAcinfo()
    {
        return acinfo;
    }

    public AlgorithmIdentifier getSignatureAlgorithm()
    {
        return signatureAlgorithm;
    }

    public DERBitString getSignatureValue()
    {
        return signatureValue;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  AttributeCertificate ::= SEQUENCE {
     *       acinfo               AttributeCertificateInfo,
     *       signatureAlgorithm   AlgorithmIdentifier,
     *       signatureValue       BIT STRING
     *  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(acinfo);
        v.add(signatureAlgorithm);
        v.add(signatureValue);

        return new DERSequence(v);
    }
}