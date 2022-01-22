package com.github.zhenwei.sdk.util.asn1.cms;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import java.math.BigInteger;

/**
 * RFC 5990 RSA KEM parameters class.
 * <pre>
 *  RsaKemParameters ::= SEQUENCE {
 *     keyDerivationFunction  KeyDerivationFunction,
 *     keyLength              KeyLength
 *   }
 *
 *   KeyDerivationFunction ::= AlgorithmIdentifier
 *   KeyLength ::= INTEGER (1..MAX)
 * </pre>
 */
public class RsaKemParameters
    extends ASN1Object
{
    private final AlgorithmIdentifier keyDerivationFunction;
    private final BigInteger keyLength;

    private RsaKemParameters(ASN1Sequence sequence)
    {
        if (sequence.size() != 2)
        {
            throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
        }
        this.keyDerivationFunction = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
        this.keyLength = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
    }

    public static cms.RsaKemParameters getInstance(
        Object  o)
    {
        if (o instanceof cms.RsaKemParameters)
        {
            return (cms.RsaKemParameters)o;
        }
        else if (o != null)
        {
            return new cms.RsaKemParameters(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    /**
     * Base constructor.
     *
     * @param keyDerivationFunction algorithm ID describing the key derivation function.
     * @param keyLength length of key to be derived (in bytes).
     */
    public RsaKemParameters(AlgorithmIdentifier keyDerivationFunction, int keyLength)
    {
        this.keyDerivationFunction = keyDerivationFunction;
        this.keyLength = BigInteger.valueOf(keyLength);
    }

    public AlgorithmIdentifier getKeyDerivationFunction()
    {
        return keyDerivationFunction;
    }

    public BigInteger getKeyLength()
    {
        return keyLength;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(2);

        v.add(keyDerivationFunction);
        v.add(new ASN1Integer(keyLength));

        return new DERSequence(v);
    }
}