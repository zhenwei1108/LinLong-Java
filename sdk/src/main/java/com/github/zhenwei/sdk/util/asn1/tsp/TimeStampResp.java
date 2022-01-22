package com.github.zhenwei.sdk.util.asn1.tsp;


import cmp.PKIStatusInfo;
import cms.ContentInfo;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import java.util.Enumeration;


public class TimeStampResp
    extends ASN1Object
{
    PKIStatusInfo pkiStatusInfo;

    ContentInfo timeStampToken;

    public static tsp.TimeStampResp getInstance(Object o)
    {
        if (o instanceof tsp.TimeStampResp)
        {
            return (tsp.TimeStampResp) o;
        }
        else if (o != null)
        {
            return new tsp.TimeStampResp(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private TimeStampResp(ASN1Sequence seq)
    {

        Enumeration e = seq.getObjects();

        // status
        pkiStatusInfo = PKIStatusInfo.getInstance(e.nextElement());

        if (e.hasMoreElements())
        {
            timeStampToken = ContentInfo.getInstance(e.nextElement());
        }
    }

    public TimeStampResp(PKIStatusInfo pkiStatusInfo, ContentInfo timeStampToken)
    {
        this.pkiStatusInfo = pkiStatusInfo;
        this.timeStampToken = timeStampToken;
    }

    public PKIStatusInfo getStatus()
    {
        return pkiStatusInfo;
    }

    public ContentInfo getTimeStampToken()
    {
        return timeStampToken;
    }

    /**
     * <pre>
     * TimeStampResp ::= SEQUENCE  {
     *   status                  PKIStatusInfo,
     *   timeStampToken          TimeStampToken     OPTIONAL  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        
        v.add(pkiStatusInfo);
        if (timeStampToken != null)
        {
            v.add(timeStampToken);
        }

        return new DERSequence(v);
    }
}