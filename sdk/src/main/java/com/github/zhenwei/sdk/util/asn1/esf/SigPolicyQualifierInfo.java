package com.github.zhenwei.sdk.util.asn1.esf;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;

public class SigPolicyQualifierInfo
    extends ASN1Object
{
    private ASN1ObjectIdentifier sigPolicyQualifierId;
    private ASN1Encodable sigQualifier;

    public SigPolicyQualifierInfo(
        ASN1ObjectIdentifier   sigPolicyQualifierId,
        ASN1Encodable          sigQualifier)
    {
        this.sigPolicyQualifierId = sigPolicyQualifierId;
        this.sigQualifier = sigQualifier;
    }

    private SigPolicyQualifierInfo(
        ASN1Sequence seq)
    {
        sigPolicyQualifierId = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        sigQualifier = seq.getObjectAt(1);
    }

    public static esf.SigPolicyQualifierInfo getInstance(
        Object obj)
    {
        if (obj instanceof esf.SigPolicyQualifierInfo)
        {
            return (esf.SigPolicyQualifierInfo) obj;
        }
        else if (obj != null)
        {
            return new esf.SigPolicyQualifierInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public ASN1ObjectIdentifier getSigPolicyQualifierId()
    {
        return new ASN1ObjectIdentifier(sigPolicyQualifierId.getId());
    }

    public ASN1Encodable getSigQualifier()
    {
        return sigQualifier;
    }

    /**
     * <pre>
     * SigPolicyQualifierInfo ::= SEQUENCE {
     *    sigPolicyQualifierId SigPolicyQualifierId,
     *    sigQualifier ANY DEFINED BY sigPolicyQualifierId }
     *
     * SigPolicyQualifierId ::= OBJECT IDENTIFIER
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(sigPolicyQualifierId);
        v.add(sigQualifier);

        return new DERSequence(v);
    }
}