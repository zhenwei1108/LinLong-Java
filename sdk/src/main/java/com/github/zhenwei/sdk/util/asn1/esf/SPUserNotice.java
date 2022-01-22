package com.github.zhenwei.sdk.util.asn1.esf;


import DisplayText;
import NoticeReference;
import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1String;
import com.github.zhenwei.core.asn1.DERSequence;
import java.util.Enumeration;

public class SPUserNotice
    extends ASN1Object
{
    private NoticeReference noticeRef;
    private DisplayText     explicitText;

    public static esf.SPUserNotice getInstance(
        Object obj)
    {
        if (obj instanceof esf.SPUserNotice)
        {
            return (esf.SPUserNotice)obj;
        }
        else if (obj != null)
        {
            return new esf.SPUserNotice(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SPUserNotice(
        ASN1Sequence seq)
    {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements())
        {
            ASN1Encodable object = (ASN1Encodable)e.nextElement();
            if (object instanceof DisplayText || object instanceof ASN1String)
            {
                explicitText = DisplayText.getInstance(object);
            }
            else if (object instanceof NoticeReference || object instanceof ASN1Sequence)
            {
                noticeRef = NoticeReference.getInstance(object);
            }
            else
            {
                throw new IllegalArgumentException("Invalid element in 'SPUserNotice': " + object.getClass().getName());
            }
        }
    }

    public SPUserNotice(
        NoticeReference noticeRef,
        DisplayText     explicitText)
    {
        this.noticeRef = noticeRef;
        this.explicitText = explicitText;
    }

    public NoticeReference getNoticeRef()
    {
        return noticeRef;
    }

    public DisplayText getExplicitText()
    {
        return explicitText;
    }

    /**
     * <pre>
     * SPUserNotice ::= SEQUENCE {
     *     noticeRef NoticeReference OPTIONAL,
     *     explicitText DisplayText OPTIONAL }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (noticeRef != null)
        {
            v.add(noticeRef);
        }

        if (explicitText != null)
        {
            v.add(explicitText);
        }

        return new DERSequence(v);
    }
}