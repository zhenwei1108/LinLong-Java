package com.github.zhenwei.pkix.util.asn1.cms;


import X500Name;
import X509CertificateStructure;
import X509Name;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.math.BigInteger;

/**
 * <a href="https://tools.ietf.org/html/rfc5652#section-10.2.4">RFC 5652</a>: IssuerAndSerialNumber object.
 * <p>
 * <pre>
 * IssuerAndSerialNumber ::= SEQUENCE {
 *     issuer Name,
 *     serialNumber CertificateSerialNumber
 * }
 *
 * CertificateSerialNumber ::= INTEGER  -- See RFC 5280
 * </pre>
 */
public class IssuerAndSerialNumber
    extends ASN1Object
{
    private X500Name    name;
    private ASN1Integer serialNumber;

    /**
     * Return an IssuerAndSerialNumber object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link cms.IssuerAndSerialNumber} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with IssuerAndSerialNumber structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static cms.IssuerAndSerialNumber getInstance(
        Object  obj)
    {
        if (obj instanceof cms.IssuerAndSerialNumber)
        {
            return (cms.IssuerAndSerialNumber)obj;
        }
        else if (obj != null)
        {
            return new cms.IssuerAndSerialNumber(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    /**
     * @deprecated  use getInstance() method.
     */
    public IssuerAndSerialNumber(
        ASN1Sequence    seq)
    {
        this.name = X500Name.getInstance(seq.getObjectAt(0));
        this.serialNumber = (ASN1Integer)seq.getObjectAt(1);
    }

    public IssuerAndSerialNumber(
        Certificate certificate)
    {
        this.name = certificate.getIssuer();
        this.serialNumber = certificate.getSerialNumber();
    }

    /**
     * @deprecated use constructor taking Certificate
     */
    public IssuerAndSerialNumber(
        X509CertificateStructure certificate)
    {
        this.name = certificate.getIssuer();
        this.serialNumber = certificate.getSerialNumber();
    }

    public IssuerAndSerialNumber(
        X500Name name,
        BigInteger  serialNumber)
    {
        this.name = name;
        this.serialNumber = new ASN1Integer(serialNumber);
    }

    /**
     * @deprecated use X500Name constructor
     */
    public IssuerAndSerialNumber(
        X509Name    name,
        BigInteger  serialNumber)
    {
        this.name = X500Name.getInstance(name);
        this.serialNumber = new ASN1Integer(serialNumber);
    }

    /**
     * @deprecated use X500Name constructor
     */
    public IssuerAndSerialNumber(
        X509Name    name,
        ASN1Integer  serialNumber)
    {
        this.name = X500Name.getInstance(name);
        this.serialNumber = serialNumber;
    }

    public X500Name getName()
    {
        return name;
    }

    public ASN1Integer getSerialNumber()
    {
        return serialNumber;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(name);
        v.add(serialNumber);

        return new DERSequence(v);
    }
}