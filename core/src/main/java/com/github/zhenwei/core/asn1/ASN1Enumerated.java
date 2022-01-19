package com.github.zhenwei.core.asn1;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.util.Arrays;

/**
 * Class representing the ASN.1 ENUMERATED type.
 */
public class ASN1Enumerated
    extends ASN1Primitive
{
    static final ASN1UniversalType TYPE = new ASN1UniversalType(
        org.bouncycastle.asn1.ASN1Enumerated.class, BERTags.ENUMERATED)
    {
        ASN1Primitive fromImplicitPrimitive(DEROctetString octetString)
        {
            return createPrimitive(octetString.getOctets(), false);
        }
    };

    /**
     * return an enumerated from the passed in object
     *
     * @param obj an ASN1Enumerated or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return an ASN1Enumerated instance, or null.
     */
    public static org.bouncycastle.asn1.ASN1Enumerated getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof org.bouncycastle.asn1.ASN1Enumerated)
        {
            return (org.bouncycastle.asn1.ASN1Enumerated)obj;
        }

        if (obj instanceof byte[])
        {
            try
            {
                return (org.bouncycastle.asn1.ASN1Enumerated)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * return an Enumerated from a tagged object.
     *
     * @param taggedObject the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly
     *              tagged false otherwise.
     * @exception IllegalArgumentException if the tagged object cannot
     *               be converted.
     * @return an ASN1Enumerated instance, or null.
     */
    public static org.bouncycastle.asn1.ASN1Enumerated getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (org.bouncycastle.asn1.ASN1Enumerated)TYPE.getContextInstance(taggedObject, explicit);
    }

    private final byte[] contents;
    private final int start;

    /**
     * Constructor from int.
     *
     * @param value the value of this enumerated.
     */
    public ASN1Enumerated(int value)
    {
        if (value < 0)
        {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }

        this.contents = BigInteger.valueOf(value).toByteArray();
        this.start = 0;
    }

    /**
     * Constructor from BigInteger
     *
     * @param value the value of this enumerated.
     */
    public ASN1Enumerated(BigInteger value)
    {
        if (value.signum() < 0)
        {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }

        this.contents = value.toByteArray();
        this.start = 0;
    }

    /**
     * Constructor from encoded BigInteger.
     *
     * @param contents the value of this enumerated as an encoded BigInteger (signed).
     */
    public ASN1Enumerated(byte[] contents)
    {
        this(contents, true);
    }

    ASN1Enumerated(byte[] contents, boolean clone)
    {
        if (ASN1Integer.isMalformed(contents))
        {
            throw new IllegalArgumentException("malformed enumerated");
        }
        if (0 != (contents[0] & 0x80))
        {
            throw new IllegalArgumentException("enumerated must be non-negative");
        }

        this.contents = clone ? Arrays.clone(contents) : contents;
        this.start = ASN1Integer.signBytesToSkip(contents);
    }

    public BigInteger getValue()
    {
        return new BigInteger(contents);
    }

    public boolean hasValue(int x)
    {
        return (contents.length - start) <= 4
            && ASN1Integer.intValue(contents, start, ASN1Integer.SIGN_EXT_SIGNED) == x;
    }

    public boolean hasValue(BigInteger x)
    {
        return null != x
            // Fast check to avoid allocation
            && ASN1Integer.intValue(contents, start, ASN1Integer.SIGN_EXT_SIGNED) == x.intValue()
            && getValue().equals(x);
    }

    public int intValueExact()
    {
        int count = contents.length - start;
        if (count > 4)
        {
            throw new ArithmeticException("ASN.1 Enumerated out of int range");
        }

        return ASN1Integer.intValue(contents, start, ASN1Integer.SIGN_EXT_SIGNED);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.ENUMERATED, contents);
    }

    boolean asn1Equals(
        ASN1Primitive  o)
    {
        if (!(o instanceof org.bouncycastle.asn1.ASN1Enumerated))
        {
            return false;
        }

        org.bouncycastle.asn1.ASN1Enumerated other = (org.bouncycastle.asn1.ASN1Enumerated)o;

        return Arrays.areEqual(this.contents, other.contents);
    }

    public int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    private static final org.bouncycastle.asn1.ASN1Enumerated[] cache = new org.bouncycastle.asn1.ASN1Enumerated[12];

    static org.bouncycastle.asn1.ASN1Enumerated createPrimitive(byte[] contents, boolean clone)
    {
        if (contents.length > 1)
        {
            return new org.bouncycastle.asn1.ASN1Enumerated(contents, clone);
        }

        if (contents.length == 0)
        {
            throw new IllegalArgumentException("ENUMERATED has zero length");
        }
        int value = contents[0] & 0xff;

        if (value >= cache.length)
        {
            return new org.bouncycastle.asn1.ASN1Enumerated(contents, clone);
        }

        org.bouncycastle.asn1.ASN1Enumerated possibleMatch = cache[value];

        if (possibleMatch == null)
        {
            possibleMatch = cache[value] = new org.bouncycastle.asn1.ASN1Enumerated(contents, clone);
        }

        return possibleMatch;
    }
}