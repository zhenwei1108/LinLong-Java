package com.github.zhenwei.sdk.util.asn1.cmp;





public class CertConfirmContent
    extends ASN1Object
{
    private ASN1Sequence content;

    private CertConfirmContent(ASN1Sequence seq)
    {
        content = seq;
    }

    public static cmp.CertConfirmContent getInstance(Object o)
    {
        if (o instanceof cmp.CertConfirmContent)
        {
            return (cmp.CertConfirmContent)o;
        }

        if (o != null)
        {
            return new cmp.CertConfirmContent(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public CertStatus[] toCertStatusArray()
    {
        CertStatus[] result = new CertStatus[content.size()];

        for (int i = 0; i != result.length; i++)
        {
            result[i] = CertStatus.getInstance(content.getObjectAt(i));
        }

        return result;
    }
    
    /**
     * <pre>
     * CertConfirmContent ::= SEQUENCE OF CertStatus
     * </pre>
     * @return a basic ASN.1 object representation.
     */
    public ASN1Primitive toASN1Primitive()
    {
        return content;
    }
}