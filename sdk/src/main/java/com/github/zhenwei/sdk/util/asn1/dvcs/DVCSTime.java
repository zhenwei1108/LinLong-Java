package com.github.zhenwei.sdk.util.asn1.dvcs;

import java.util.Date;
import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;

/**
 * <pre>
 *     DVCSTime ::= CHOICE  {
 *         genTime                      GeneralizedTime,
 *         timeStampToken               ContentInfo
 *     }
 * </pre>
 */
public class DVCSTime
    extends ASN1Object
    implements ASN1Choice
{
    private final ASN1GeneralizedTime genTime;
    private final ContentInfo timeStampToken;

    // constructors:

    public DVCSTime(Date time)
    {
        this(new ASN1GeneralizedTime(time));
    }

    public DVCSTime(ASN1GeneralizedTime genTime)
    {
        this.genTime = genTime;
        this.timeStampToken = null;
    }

    public DVCSTime(ContentInfo timeStampToken)
    {
        this.genTime = null;
        this.timeStampToken = timeStampToken;
    }

    public static org.bouncycastle.asn1.dvcs.DVCSTime getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.dvcs.DVCSTime)
        {
            return (org.bouncycastle.asn1.dvcs.DVCSTime)obj;
        }
        else if (obj instanceof ASN1GeneralizedTime)
        {
            return new org.bouncycastle.asn1.dvcs.DVCSTime(ASN1GeneralizedTime.getInstance(obj));
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.dvcs.DVCSTime(ContentInfo.getInstance(obj));
        }

        return null;
    }

    public static org.bouncycastle.asn1.dvcs.DVCSTime getInstance(
        ASN1TaggedObject obj,
        boolean explicit)
    {
        return getInstance(obj.getObject()); // must be explicitly tagged
    }


    // selectors:

    public ASN1GeneralizedTime getGenTime()
    {
        return genTime;
    }

    public ContentInfo getTimeStampToken()
    {
        return timeStampToken;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (genTime != null)
        {
            return genTime;
        }
        else
        {
            return timeStampToken.toASN1Primitive();
        }
    }

    public String toString()
    {
        if (genTime != null)
        {
            return genTime.toString();
        }
        else
        {
            return timeStampToken.toString();
        }
    }
}