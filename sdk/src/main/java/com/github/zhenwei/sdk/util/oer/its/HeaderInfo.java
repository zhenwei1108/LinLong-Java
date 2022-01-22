package com.github.zhenwei.sdk.util.oer.its;






/**
 * <pre>
 *     HeaderInfo ::= SEQUENCE {
 *         psid Psid,
 *         generationTime Time64 OPTIONAL,
 *         expiryTime Time64 OPTIONAL,
 *         generationLocation ThreeDLocation OPTIONAL,
 *         p2pcdLearningRequest HashedId3 OPTIONAL,
 *         missingCrlIdentifier MissingCrlIdentifier OPTIONAL,
 *         ...,
 *         inlineP2pcdRequest SequenceOfHashedId3 OPTIONAL,
 *         requestedCertificate Certificate OPTIONAL
 *     }
 * </pre>
 */
public class HeaderInfo
    extends ASN1Object
{


    //TODO needs implementing.
    public static HeaderInfo getInstance(Object o)
    {
        if (o instanceof HeaderInfo)
        {
            return (HeaderInfo)o;
        }
        else if (o != null)
        {
            //return new HeaderInfo(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        return new DERSequence(v);
    }
}