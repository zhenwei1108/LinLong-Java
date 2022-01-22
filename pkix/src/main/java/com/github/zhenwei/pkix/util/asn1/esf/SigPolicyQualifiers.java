package com.github.zhenwei.pkix.util.asn1.esf;


import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;

public class SigPolicyQualifiers
    extends ASN1Object
{
    ASN1Sequence qualifiers;

    public static esf.SigPolicyQualifiers getInstance(
        Object obj)
    {
        if (obj instanceof esf.SigPolicyQualifiers)
        {
            return (esf.SigPolicyQualifiers) obj;
        }
        else if (obj instanceof ASN1Sequence)
        {
            return new esf.SigPolicyQualifiers(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    private SigPolicyQualifiers(
        ASN1Sequence seq)
    {
        qualifiers = seq;
    }

    public SigPolicyQualifiers(
        SigPolicyQualifierInfo[] qualifierInfos)
    {
        qualifiers = new DERSequence(qualifierInfos);
    }

    /**
     * Return the number of qualifier info elements present.
     *
     * @return number of elements present.
     */
    public int size()
    {
        return qualifiers.size();
    }

    /**
     * Return the SigPolicyQualifierInfo at index i.
     *
     * @param i index of the info of interest
     * @return the info at index i.
     */
    public SigPolicyQualifierInfo getInfoAt(
        int i)
    {
        return SigPolicyQualifierInfo.getInstance(qualifiers.getObjectAt(i));
    }

    /**
     * <pre>
     * SigPolicyQualifiers ::= SEQUENCE SIZE (1..MAX) OF SigPolicyQualifierInfo
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return qualifiers;
    }
}