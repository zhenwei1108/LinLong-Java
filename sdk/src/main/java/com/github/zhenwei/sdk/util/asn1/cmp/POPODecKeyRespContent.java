package com.github.zhenwei.sdk.util.asn1.cmp;






public class POPODecKeyRespContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private POPODecKeyRespContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static cmp.POPODecKeyRespContent getInstance(Object o)
    {
        if (o instanceof cmp.POPODecKeyRespContent)
        {
            return (cmp.POPODecKeyRespContent)o;
        }

        if (o != null)
        {
            return new cmp.POPODecKeyRespContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public ASN1Integer[] toASN1IntegerArray()
    {
        ASN1Integer[] result = new ASN1Integer[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = ASN1Integer.getInstance(content.getObjectAt(i));
        }

        return result;
    }

    /**
     * <pre>
     * POPODecKeyRespContent ::= SEQUENCE OF INTEGER
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}