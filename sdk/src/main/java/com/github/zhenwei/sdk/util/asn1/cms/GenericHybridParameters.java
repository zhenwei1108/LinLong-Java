package com.github.zhenwei.sdk.util.asn1.cms;








/**
 * RFC 5990 GenericHybridParameters class.
 * <pre>
 * GenericHybridParameters ::= SEQUENCE {
 *    kem  KeyEncapsulationMechanism,
 *    dem  DataEncapsulationMechanism
 * }
 *
 * KeyEncapsulationMechanism ::= AlgorithmIdentifier {{KEMAlgorithms}}
 * DataEncapsulationMechanism ::= AlgorithmIdentifier {{DEMAlgorithms}}
 * </pre>
 */
public class GenericHybridParameters
    extends ASN1Object
{
    private final AlgorithmIdentifier kem;
    private final AlgorithmIdentifier dem;

    private GenericHybridParameters(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
        }

        this.kem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        this.dem = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
    }

    public static cms.GenericHybridParameters getInstance(
        Object  o)
    {
        if (o instanceof cms.GenericHybridParameters)
        {
            return (cms.GenericHybridParameters)o;
        }
        else if (o != null)
        {
            return new cms.GenericHybridParameters(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public GenericHybridParameters(AlgorithmIdentifier kem, AlgorithmIdentifier dem)
    {
        this.kem = kem;
        this.dem = dem;
    }

    public AlgorithmIdentifier getDem()
    {
        return dem;
    }

    public AlgorithmIdentifier getKem()
    {
        return kem;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(kem);
        v.add(dem);

        return new DERSequence(v);
    }
}