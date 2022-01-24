package com.github.zhenwei.pkix.util.asn1.cmc;

import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.util.Arrays;

/**
 * <pre>
 *      id-cmc-popLinkWitnessV2 OBJECT IDENTIFIER ::= { id-cmc 33 }
 *      PopLinkWitnessV2 ::= SEQUENCE {
 *           keyGenAlgorithm   AlgorithmIdentifier,
 *           macAlgorithm      AlgorithmIdentifier,
 *           witness           OCTET STRING
 *      }
 * </pre>
 */
public class PopLinkWitnessV2
    extends ASN1Object
{
    private final AlgorithmIdentifier keyGenAlgorithm;
    private final AlgorithmIdentifier macAlgorithm;
    private final byte[] witness;

    public PopLinkWitnessV2(AlgorithmIdentifier keyGenAlgorithm, AlgorithmIdentifier macAlgorithm, byte[] witness)
    {
        this.keyGenAlgorithm = keyGenAlgorithm;
        this.macAlgorithm = macAlgorithm;
        this.witness = Arrays.clone(witness);
    }

    private PopLinkWitnessV2(ASN1Sequence seq)
    {
        if (seq.size() != 3)
        {
            throw new IllegalArgumentException("incorrect sequence size");
        }
        this.keyGenAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets());
    }

    public static PopLinkWitnessV2 getInstance(Object o)
    {
        if (o instanceof PopLinkWitnessV2)
        {
            return (PopLinkWitnessV2)o;
        }

        if (o != null)
        {
            return new PopLinkWitnessV2(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    public AlgorithmIdentifier getKeyGenAlgorithm()
    {
        return keyGenAlgorithm;
    }

    public AlgorithmIdentifier getMacAlgorithm()
    {
        return macAlgorithm;
    }

    public byte[] getWitness()
    {
        return Arrays.clone(witness);
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(3);

        v.add(keyGenAlgorithm);
        v.add(macAlgorithm);
        v.add(new DEROctetString(getWitness()));

        return new DERSequence(v);
    }
}