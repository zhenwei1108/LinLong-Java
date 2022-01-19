package com.github.zhenwei.sdk.util.asn1.esf;

import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.esf.SignaturePolicyId;

public class SignaturePolicyIdentifier
    extends ASN1Object
{
    private SignaturePolicyId   signaturePolicyId;
    private boolean             isSignaturePolicyImplied;

    public static org.bouncycastle.asn1.esf.SignaturePolicyIdentifier getInstance(
        Object  obj)
    {
        if (obj instanceof org.bouncycastle.asn1.esf.SignaturePolicyIdentifier)
        {
            return (org.bouncycastle.asn1.esf.SignaturePolicyIdentifier)obj;
        }
        else if (obj instanceof ASN1Null || hasEncodedTagValue(obj, BERTags.NULL))
        {
            return new org.bouncycastle.asn1.esf.SignaturePolicyIdentifier();
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.esf.SignaturePolicyIdentifier(SignaturePolicyId.getInstance(obj));
        }

        return null;
    }

    public SignaturePolicyIdentifier()
    {
        this.isSignaturePolicyImplied = true;
    }

    public SignaturePolicyIdentifier(
        SignaturePolicyId signaturePolicyId)
    {
        this.signaturePolicyId = signaturePolicyId;
        this.isSignaturePolicyImplied = false;
    }

    public SignaturePolicyId getSignaturePolicyId()
    {
        return signaturePolicyId;
    }

    public boolean isSignaturePolicyImplied()
    {
        return isSignaturePolicyImplied;
    }

    /**
     * <pre>
     * SignaturePolicyIdentifier ::= CHOICE{
     *     SignaturePolicyId         SignaturePolicyId,
     *     SignaturePolicyImplied    SignaturePolicyImplied }
     *
     * SignaturePolicyImplied ::= NULL
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        if (isSignaturePolicyImplied)
        {
            return DERNull.INSTANCE;
        }
        else
        {
            return signaturePolicyId.toASN1Primitive();
        }
    }
}