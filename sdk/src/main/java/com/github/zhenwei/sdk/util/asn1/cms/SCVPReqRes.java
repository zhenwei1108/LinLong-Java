package com.github.zhenwei.sdk.util.asn1.cms;









/**
 * <a href="https://tools.ietf.org/html/rfc5940">RFC 5940</a>:
 * Additional Cryptographic Message Syntax (CMS) Revocation Information Choices.
 * <p>
 * <pre>
 * SCVPReqRes ::= SEQUENCE {
 *     request  [0] EXPLICIT ContentInfo OPTIONAL,
 *     response     ContentInfo }
 * </pre>
 */
public class SCVPReqRes
    extends ASN1Object
{
    private final ContentInfo request;
    private final ContentInfo response;

    /**
     * Return a SCVPReqRes object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link cms.SCVPReqRes} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with SCVPReqRes structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static cms.SCVPReqRes getInstance(
        Object  obj)
    {
        if (obj instanceof cms.SCVPReqRes)
        {
            return (cms.SCVPReqRes)obj;
        }
        else if (obj != null)
        {
            return new cms.SCVPReqRes(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SCVPReqRes(
        ASN1Sequence seq)
    {
        if (seq.getObjectAt(0) instanceof ASN1TaggedObject)
        {
            this.request = ContentInfo.getInstance(ASN1TaggedObject.getInstance(seq.getObjectAt(0)), true);
            this.response = ContentInfo.getInstance(seq.getObjectAt(1));
        }
        else
        {
            this.request = null;
            this.response = ContentInfo.getInstance(seq.getObjectAt(0));
        }
    }

    public SCVPReqRes(ContentInfo response)
    {
        this.request = null;       // use of this confuses earlier JDKs
        this.response = response;
    }

    public SCVPReqRes(ContentInfo request, ContentInfo response)
    {
        this.request = request;
        this.response = response;
    }

    public ContentInfo getRequest()
    {
        return request;
    }

    public ContentInfo getResponse()
    {
        return response;
    }

    /**
     * @return  the ASN.1 primitive representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        if (request != null)
        {
            v.add(new DERTaggedObject(true, 0, request));
        }

        v.add(response);

        return new DERSequence(v);
    }
}