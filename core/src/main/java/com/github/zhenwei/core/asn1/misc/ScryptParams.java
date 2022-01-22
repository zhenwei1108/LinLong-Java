package com.github.zhenwei.core.asn1.misc;


import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1Object;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.util.Arrays;
import java.math.BigInteger;


/**
 * RFC 7914 scrypt parameters.
 *
 * <pre>
 * scrypt-params ::= SEQUENCE {
 *      salt OCTET STRING,
 *      costParameter INTEGER (1..MAX),
 *      blockSize INTEGER (1..MAX),
 *      parallelizationParameter INTEGER (1..MAX),
 *      keyLength INTEGER (1..MAX) OPTIONAL
 * }
 * </pre>
 */
public class ScryptParams
    extends ASN1Object
{
    private final byte[] salt;
    private final BigInteger costParameter;
    private final BigInteger blockSize;
    private final BigInteger parallelizationParameter;
    private final BigInteger keyLength;

    public ScryptParams(byte[] salt, int costParameter, int blockSize, int parallelizationParameter)
    {
        this(salt, BigInteger.valueOf(costParameter), BigInteger.valueOf(blockSize), BigInteger.valueOf(parallelizationParameter), null);
    }

    public ScryptParams(byte[] salt, int costParameter, int blockSize, int parallelizationParameter, int keyLength)
    {
        this(salt, BigInteger.valueOf(costParameter), BigInteger.valueOf(blockSize), BigInteger.valueOf(parallelizationParameter), BigInteger.valueOf(keyLength));
    }
    
    /**
     * Base constructor.
     *
     * @param salt salt value
     * @param costParameter specifies the CPU/Memory cost parameter N
     * @param blockSize block size parameter r
     * @param parallelizationParameter parallelization parameter
     * @param keyLength length of key to be derived (in octects)
     */
    public ScryptParams(byte[] salt, BigInteger costParameter, BigInteger blockSize, BigInteger parallelizationParameter, BigInteger keyLength)
    {
        this.salt = Arrays.clone(salt);
        this.costParameter = costParameter;
        this.blockSize = blockSize;
        this.parallelizationParameter = parallelizationParameter;
        this.keyLength = keyLength;
    }

    public static misc.ScryptParams getInstance(
        Object  o)
    {
        if (o instanceof misc.ScryptParams)
        {
            return (misc.ScryptParams)o;
        }
        else if (o != null)
        {
            return new misc.ScryptParams(ASN1Sequence.getInstance(o));
        }

        return null;
    }

    private ScryptParams(ASN1Sequence seq)
    {
        if (seq.size() != 4 && seq.size() != 5)
        {
            throw new IllegalArgumentException("invalid sequence: size = " + seq.size());
        }

        this.salt = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
        this.costParameter = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
        this.blockSize = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
        this.parallelizationParameter = ASN1Integer.getInstance(seq.getObjectAt(3)).getValue();

        if (seq.size() == 5)
        {
            this.keyLength = ASN1Integer.getInstance(seq.getObjectAt(4)).getValue();
        }
        else
        {
            this.keyLength = null;
        }
    }

    public byte[] getSalt()
    {
        return Arrays.clone(salt);
    }

    public BigInteger getCostParameter()
    {
        return costParameter;
    }

    public BigInteger getBlockSize()
    {
        return blockSize;
    }

    public BigInteger getParallelizationParameter()
    {
        return parallelizationParameter;
    }

    /**
     * Return the length in octets for the derived key.
     *
     * @return length for key to be derived (in octets)
     */
    public BigInteger getKeyLength()
    {
        return keyLength;
    }

    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector(5);

        v.add(new DEROctetString(salt));
        v.add(new ASN1Integer(costParameter));
        v.add(new ASN1Integer(blockSize));
        v.add(new ASN1Integer(parallelizationParameter));
        if (keyLength != null)
        {
            v.add(new ASN1Integer(keyLength));
        }

        return new DERSequence(v);
    }
}