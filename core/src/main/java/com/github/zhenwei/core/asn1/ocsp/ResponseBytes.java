package com.github.zhenwei.core.asn1.ocsp;










/**
 * OCSP RFC 2560, RFC 6960
 * <pre>
 * ResponseBytes ::=       SEQUENCE {
 *     responseType   OBJECT IDENTIFIER,
 *     response       OCTET STRING }
 * </pre>
 */
public class ResponseBytes
    extends ASN1Object
{
    ASN1ObjectIdentifier    responseType;
    ASN1OctetString        response;

    public ResponseBytes(
        ASN1ObjectIdentifier responseType,
        ASN1OctetString     response)
    {
        this.responseType = responseType;
        this.response = response;
    }

    private ResponseBytes(
        ASN1Sequence    seq)
    {
        responseType = (ASN1ObjectIdentifier)seq.getObjectAt(0);
        response = (ASN1OctetString)seq.getObjectAt(1);
    }

    public static ocsp.ResponseBytes getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ocsp.ResponseBytes getInstance(
        Object  obj)
    {
        if (obj instanceof ocsp.ResponseBytes)
        {
            return (ocsp.ResponseBytes)obj;
        }
        else if (obj != null)
        {
            return new ocsp.ResponseBytes(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getResponseType()
    {
        return responseType;
    }

    public ASN1OctetString getResponse()
    {
        return response;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * ResponseBytes ::=       SEQUENCE {
     *     responseType   OBJECT IDENTIFIER,
     *     response       OCTET STRING }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(responseType);
        v.add(response);

        return new DERSequence(v);
    }
}