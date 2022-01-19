package com.github.zhenwei.core.asn1.ocsp;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.x509.Extensions;

public class Request
    extends ASN1Object
{
    CertID            reqCert;
    Extensions    singleRequestExtensions;

    public Request(
        CertID          reqCert,
        Extensions singleRequestExtensions)
    {
        this.reqCert = reqCert;
        this.singleRequestExtensions = singleRequestExtensions;
    }

    private Request(
        ASN1Sequence    seq)
    {
        reqCert = CertID.getInstance(seq.getObjectAt(0));

        if (seq.size() == 2)
        {
            singleRequestExtensions = Extensions.getInstance(
                                (ASN1TaggedObject)seq.getObjectAt(1), true);
        }
    }

    public static org.bouncycastle.asn1.ocsp.Request getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static org.bouncycastle.asn1.ocsp.Request getInstance(
        Object  obj)
    {
        if (obj instanceof org.bouncycastle.asn1.ocsp.Request)
        {
            return (org.bouncycastle.asn1.ocsp.Request)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.ocsp.Request(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public CertID getReqCert()
    {
        return reqCert;
    }

    public Extensions getSingleRequestExtensions()
    {
        return singleRequestExtensions;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Request         ::=     SEQUENCE {
     *     reqCert                     CertID,
     *     singleRequestExtensions     [0] EXPLICIT Extensions OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(reqCert);

        if (singleRequestExtensions != null)
        {
            v.add(new DERTaggedObject(true, 0, singleRequestExtensions));
        }

        return new DERSequence(v);
    }
}