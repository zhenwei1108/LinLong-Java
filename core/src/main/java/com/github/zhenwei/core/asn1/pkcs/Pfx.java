package com.github.zhenwei.core.asn1.pkcs;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.pkcs.ContentInfo;
import org.bouncycastle.asn1.pkcs.MacData;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

/**
 * the infamous Pfx from PKCS12
 */
public class Pfx
    extends ASN1Object
    implements PKCSObjectIdentifiers
{
    private ContentInfo             contentInfo;
    private MacData                 macData = null;

    private Pfx(
        ASN1Sequence   seq)
    {
        ASN1Integer version = ASN1Integer.getInstance(seq.getObjectAt(0));
        if (!version.hasValue(3))
        {
            throw new IllegalArgumentException("wrong version for PFX PDU");
        }

        contentInfo = ContentInfo.getInstance(seq.getObjectAt(1));

        if (seq.size() == 3)
        {
            macData = MacData.getInstance(seq.getObjectAt(2));
        }
    }

    public static org.bouncycastle.asn1.pkcs.Pfx getInstance(
        Object  obj)
    {
        if (obj instanceof org.bouncycastle.asn1.pkcs.Pfx)
        {
            return (org.bouncycastle.asn1.pkcs.Pfx)obj;
        }

        if (obj != null)
        {
            return new org.bouncycastle.asn1.pkcs.Pfx(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public Pfx(
        ContentInfo     contentInfo,
        MacData         macData)
    {
        this.contentInfo = contentInfo;
        this.macData = macData;
    }

    public ContentInfo getAuthSafe()
    {
        return contentInfo;
    }

    public MacData getMacData()
    {
        return macData;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(new ASN1Integer(3));
        v.add(contentInfo);

        if (macData != null)
        {
            v.add(macData);
        }

        return new BERSequence(v);
    }
}