package com.github.zhenwei.sdk.util.asn1.esf;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

public class CommitmentTypeIndication
    extends ASN1Object
{
    private ASN1ObjectIdentifier   commitmentTypeId;
    private ASN1Sequence          commitmentTypeQualifier;
    
    private CommitmentTypeIndication(
        ASN1Sequence seq)
    {
        commitmentTypeId = (ASN1ObjectIdentifier)seq.getObjectAt(0);

        if (seq.size() > 1)
        {
            commitmentTypeQualifier = (ASN1Sequence)seq.getObjectAt(1);
        }
    }

    public CommitmentTypeIndication(
        ASN1ObjectIdentifier commitmentTypeId)
    {
        this.commitmentTypeId = commitmentTypeId;
    }

    public CommitmentTypeIndication(
        ASN1ObjectIdentifier commitmentTypeId,
        ASN1Sequence        commitmentTypeQualifier)
    {
        this.commitmentTypeId = commitmentTypeId;
        this.commitmentTypeQualifier = commitmentTypeQualifier;
    }

    public static org.bouncycastle.asn1.esf.CommitmentTypeIndication getInstance(
        Object obj)
    {
        if (obj == null || obj instanceof org.bouncycastle.asn1.esf.CommitmentTypeIndication)
        {
            return (org.bouncycastle.asn1.esf.CommitmentTypeIndication)obj;
        }

        return new org.bouncycastle.asn1.esf.CommitmentTypeIndication(ASN1Sequence.getInstance(obj));
    }

    public ASN1ObjectIdentifier getCommitmentTypeId()
    {
        return commitmentTypeId;
    }
    
    public ASN1Sequence getCommitmentTypeQualifier()
    {
        return commitmentTypeQualifier;
    }
    
    /**
     * <pre>
     * CommitmentTypeIndication ::= SEQUENCE {
     *      commitmentTypeId   CommitmentTypeIdentifier,
     *      commitmentTypeQualifier   SEQUENCE SIZE (1..MAX) OF
     *              CommitmentTypeQualifier OPTIONAL }
     * </pre>
     */ 
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        
        v.add(commitmentTypeId);

        if (commitmentTypeQualifier != null)
        {
            v.add(commitmentTypeQualifier);
        }
        
        return new DERSequence(v);
    }
}