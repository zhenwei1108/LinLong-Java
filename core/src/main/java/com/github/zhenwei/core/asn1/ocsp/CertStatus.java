package com.github.zhenwei.core.asn1.ocsp;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.RevokedInfo;

public class CertStatus
    extends ASN1Object
    implements ASN1Choice
{
    private int             tagNo;
    private ASN1Encodable    value;

    /**
     * create a CertStatus object with a tag of zero.
     */
    public CertStatus()
    {
        tagNo = 0;
        value = DERNull.INSTANCE;
    }

    public CertStatus(
        RevokedInfo info)
    {
        tagNo = 1;
        value = info;
    }

    public CertStatus(
        int tagNo,
        ASN1Encodable    value)
    {
        this.tagNo = tagNo;
        this.value = value;
    }

    private CertStatus(
        ASN1TaggedObject    choice)
    {
        int tagNo = choice.getTagNo();

        switch (tagNo)
        {
        case 0:
            value = ASN1Null.getInstance(choice, false);
            break;
        case 1:
            value = RevokedInfo.getInstance(choice, false);
            break;
        case 2:
            // UnknownInfo ::= NULL
            value = ASN1Null.getInstance(choice, false);
            break;
        default:
            throw new IllegalArgumentException("Unknown tag encountered: " + ASN1Util.getTagText(choice));
        }

        this.tagNo = tagNo;
    }

    public static org.bouncycastle.asn1.ocsp.CertStatus getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof org.bouncycastle.asn1.ocsp.CertStatus)
        {
            return (org.bouncycastle.asn1.ocsp.CertStatus)obj;
        }
        else if (obj instanceof ASN1TaggedObject)
        {
            return new org.bouncycastle.asn1.ocsp.CertStatus((ASN1TaggedObject)obj);
        }

        throw new IllegalArgumentException("unknown object in factory: " + obj.getClass().getName());
    }

    public static org.bouncycastle.asn1.ocsp.CertStatus getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(obj.getObject()); // must be explicitly tagged
    }
    
    public int getTagNo()
    {
        return tagNo;
    }

    public ASN1Encodable getStatus()
    {
        return value;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  CertStatus ::= CHOICE {
     *                  good        [0]     IMPLICIT NULL,
     *                  revoked     [1]     IMPLICIT RevokedInfo,
     *                  unknown     [2]     IMPLICIT UnknownInfo }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DERTaggedObject(false, tagNo, value);
    }
}