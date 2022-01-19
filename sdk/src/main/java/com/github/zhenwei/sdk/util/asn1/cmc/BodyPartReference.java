package com.github.zhenwei.sdk.util.asn1.cmc;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.BodyPartPath;

/**
 * <pre>
 * BodyPartReference ::= CHOICE {
 *    bodyPartID           BodyPartID,
 *    bodyPartPath         BodyPartPath
 * }
 * </pre>
 */
public class BodyPartReference
    extends ASN1Object
    implements ASN1Choice
{
    private final BodyPartID bodyPartID;
    private final BodyPartPath bodyPartPath;

    public BodyPartReference(BodyPartID bodyPartID)
    {
        this.bodyPartID = bodyPartID;
        this.bodyPartPath = null;
    }

    public BodyPartReference(BodyPartPath bodyPartPath)
    {
        this.bodyPartID = null;
        this.bodyPartPath = bodyPartPath;
    }

    public static org.bouncycastle.asn1.cmc.BodyPartReference getInstance(
        Object  obj)
    {
        if (obj instanceof org.bouncycastle.asn1.cmc.BodyPartReference)
        {
            return (org.bouncycastle.asn1.cmc.BodyPartReference)obj;
        }

        if (obj != null)
        {
            if (obj instanceof ASN1Encodable)
            {
                ASN1Encodable asn1Prim = ((ASN1Encodable)obj).toASN1Primitive();

                if (asn1Prim instanceof ASN1Integer)
                {
                    return new org.bouncycastle.asn1.cmc.BodyPartReference(BodyPartID.getInstance(asn1Prim));
                }
                if (asn1Prim instanceof ASN1Sequence)
                {
                    return new org.bouncycastle.asn1.cmc.BodyPartReference(BodyPartPath.getInstance(asn1Prim));
                }
            }
            if (obj instanceof byte[])
            {
                try
                {
                    return getInstance(ASN1Primitive.fromByteArray((byte[])obj));
                }
                catch (IOException e)
                {
                    throw new IllegalArgumentException("unknown encoding in getInstance()");
                }
            }
            throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
        }

        return null;
    }

    public boolean isBodyPartID()
    {
        return bodyPartID != null;
    }

    public BodyPartID getBodyPartID()
    {
        return bodyPartID;
    }

    public BodyPartPath getBodyPartPath()
    {
        return bodyPartPath;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (bodyPartID != null)
        {
            return bodyPartID.toASN1Primitive();
        }
        else
        {
            return bodyPartPath.toASN1Primitive();
        }
    }
}