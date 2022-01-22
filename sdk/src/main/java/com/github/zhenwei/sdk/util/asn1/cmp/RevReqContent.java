package com.github.zhenwei.sdk.util.asn1.cmp;






public class RevReqContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private RevReqContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static cmp.RevReqContent getInstance(Object o)
    {
        if (o instanceof cmp.RevReqContent)
        {
            return (cmp.RevReqContent)o;
        }

        if (o != null)
        {
            return new cmp.RevReqContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public RevReqContent(RevDetails revDetails)
    {
        this.content = new DERSequence(revDetails);
    }

    public RevReqContent(RevDetails[] revDetailsArray)
    {
        this.content = new DERSequence(revDetailsArray);
    }

    public RevDetails[] toRevDetailsArray()
    {
        RevDetails[] result = new RevDetails[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = RevDetails.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * RevReqContent ::= SEQUENCE OF RevDetails
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}