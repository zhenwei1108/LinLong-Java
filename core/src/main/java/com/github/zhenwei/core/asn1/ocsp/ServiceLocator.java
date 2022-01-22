package com.github.zhenwei.core.asn1.ocsp;


import AuthorityInformationAccess;
import X500Name;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;

public class ServiceLocator
    extends ASN1Object
{
    private final X500Name    issuer;
    private final AuthorityInformationAccess locator;

    private ServiceLocator(ASN1Sequence sequence)
    {
        this.issuer = X500Name.getInstance(sequence.getObjectAt(0));
        if (sequence.size() == 2)
        {
            this.locator = AuthorityInformationAccess.getInstance(sequence.getObjectAt(1));
        }
        else
        {
            this.locator = null;

        }
    }

    public static ocsp.ServiceLocator getInstance(
        Object  obj)
    {
        if (obj instanceof ocsp.ServiceLocator)
        {
            return (ocsp.ServiceLocator)obj;
        }
        else if (obj != null)
        {
            return new ocsp.ServiceLocator(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public X500Name getIssuer()
    {
        return issuer;
    }

    public AuthorityInformationAccess getLocator()
    {
        return locator;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * ServiceLocator ::= SEQUENCE {
     *     issuer    Name,
     *     locator   AuthorityInfoAccessSyntax OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(issuer);

        if (locator != null)
        {
            v.add(locator);
        }

        return new DERSequence(v);
    }
}