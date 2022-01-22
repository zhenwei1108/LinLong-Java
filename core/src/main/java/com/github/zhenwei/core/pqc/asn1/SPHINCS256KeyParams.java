package com.github.zhenwei.core.pqc.asn1;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;

public class SPHINCS256KeyParams
    extends ASN1Object
{
    private final ASN1Integer version;
    private final AlgorithmIdentifier treeDigest;

    public SPHINCS256KeyParams(AlgorithmIdentifier treeDigest)
    {
        this.version = new ASN1Integer(0);
        this.treeDigest = treeDigest;
    }

    private SPHINCS256KeyParams(ASN1Sequence sequence)
    {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
    }

    public static final org.bouncycastle.pqc.asn1.SPHINCS256KeyParams getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.pqc.asn1.SPHINCS256KeyParams)
        {
            return (org.bouncycastle.pqc.asn1.SPHINCS256KeyParams)o;
        }
        else if (o != null)
        {
            return new org.bouncycastle.pqc.asn1.SPHINCS256KeyParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AlgorithmIdentifier getTreeDigest()
    {
        return  treeDigest;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(treeDigest);

        return new DERSequence(v);
    }
}