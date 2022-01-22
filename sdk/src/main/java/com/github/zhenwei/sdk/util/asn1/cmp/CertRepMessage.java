package com.github.zhenwei.sdk.util.asn1.cmp;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.DERTaggedObject;

public class CertRepMessage
    extends ASN1Object
{
    private ASN1Sequence caPubs;
    private ASN1Sequence response;

    private CertRepMessage(ASN1Sequence seq)
    {
        int index = 0;

        if (seq.size() > 1)
        {
            caPubs = ASN1Sequence.getInstance((ASN1TaggedObject)seq.getObjectAt(index++), true);
        }

        response = ASN1Sequence.getInstance(seq.getObjectAt(index));
    }

    public static cmp.CertRepMessage getInstance(Object o)
    {
        if (o instanceof cmp.CertRepMessage)
        {
            return (cmp.CertRepMessage)o;
        }

        if (o != null)
        {
            return new cmp.CertRepMessage(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertRepMessage(CMPCertificate[] caPubs, CertResponse[] response)
    {
        if (response == null)
        {
            throw new IllegalArgumentException("'response' cannot be null");
        }

        if (caPubs != null)
        {
            this.caPubs = new DERSequence(caPubs);
        }

        this.response = new DERSequence(response);
    }

    public CMPCertificate[] getCaPubs()
    {
        if (caPubs == null)
        {
            return null;
        }

        CMPCertificate[] results = new CMPCertificate[caPubs.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CMPCertificate.getInstance(caPubs.getObjectAt(i));
        }

        return results;
    }

    public CertResponse[] getResponse()
    {
        CertResponse[] results = new CertResponse[response.size()];

        for (int i = 0; i != results.length; i++)
        {
            results[i] = CertResponse.getInstance(response.getObjectAt(i));
        }

        return results;
    }

    /**
     * <pre>
     * CertRepMessage ::= SEQUENCE {
     *                          caPubs       [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
     *                                                                             OPTIONAL,
     *                          response         SEQUENCE OF CertResponse
     * }
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (caPubs != null)
        {
            v.add(new DERTaggedObject(true, 1, caPubs));
        }

        v.add(response);

        return new DERSequence(v);
    }
}