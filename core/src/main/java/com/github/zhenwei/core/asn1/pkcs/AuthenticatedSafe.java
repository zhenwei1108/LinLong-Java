package com.github.zhenwei.core.asn1.pkcs;


import DLSequence;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.BERSequence;

public class AuthenticatedSafe
    extends ASN1Object
{
    private ContentInfo[]    info;
    private boolean  isBer = true;

    private AuthenticatedSafe(
        ASN1Sequence seq)
    {
        info = new ContentInfo[seq.size()];

        for (int i = 0; i != info.length; i++)
        {
            info[i] = ContentInfo.getInstance(seq.getObjectAt(i));
        }

        isBer = seq instanceof BERSequence;
    }

    public static pkcs.AuthenticatedSafe getInstance(
        Object o)
    {
        if (o instanceof pkcs.AuthenticatedSafe)
        {
            return (pkcs.AuthenticatedSafe)o;
        }

        if (o != null)
        {
            return new pkcs.AuthenticatedSafe(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AuthenticatedSafe(
        ContentInfo[]       info)
    {
        this.info = copy(info);
    }

    public ContentInfo[] getContentInfo()
    {
        return copy(info);
    }

    private ContentInfo[] copy(ContentInfo[] infos)
    {
        ContentInfo[] tmp = new ContentInfo[infos.length];

        System.arraycopy(infos, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public ASN1Primitive toASN1Primitive()
    {
        if (isBer)
        {
            return new BERSequence(info);
        }
        else
        {
            return new DLSequence(info);
        }
    }
}