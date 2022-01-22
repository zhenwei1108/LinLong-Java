package com.github.zhenwei.core.pqc.asn1;









/**
 * XMMSMTKeyParams
 * <pre>
 *     XMMSMTKeyParams ::= SEQUENCE {
 *         version INTEGER -- 0
 *         height INTEGER
 *         layers INTEGER
 *         treeDigest AlgorithmIdentifier
 * }
 * </pre>
 */
public class XMSSMTKeyParams
    extends ASN1Object
{
    private final ASN1Integer version;
    private final int height;
    private final int layers;
    private final AlgorithmIdentifier treeDigest;

    public XMSSMTKeyParams(int height, int layers, AlgorithmIdentifier treeDigest)
    {
        this.version = new ASN1Integer(0);
        this.height = height;
        this.layers = layers;
        this.treeDigest = treeDigest;
    }

    private XMSSMTKeyParams(ASN1Sequence sequence)
    {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.height = ASN1Integer.getInstance(sequence.getObjectAt(1)).intValueExact();
        this.layers = ASN1Integer.getInstance(sequence.getObjectAt(2)).intValueExact();
        this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(3));
    }

    public static org.bouncycastle.pqc.asn1.XMSSMTKeyParams getInstance(Object o)
    {
        if (o instanceof org.bouncycastle.pqc.asn1.XMSSMTKeyParams)
        {
            return (org.bouncycastle.pqc.asn1.XMSSMTKeyParams)o;
        }
        else if (o != null)
        {
            return new org.bouncycastle.pqc.asn1.XMSSMTKeyParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public int getHeight()
    {
        return height;
    }

    public int getLayers()
    {
        return layers;
    }

    public AlgorithmIdentifier getTreeDigest()
    {
        return treeDigest;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(version);
        v.add(new ASN1Integer(height));
        v.add(new ASN1Integer(layers));
        v.add(treeDigest);

        return new DERSequence(v);
    }
}