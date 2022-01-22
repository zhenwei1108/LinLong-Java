package com.g

import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1OutputStream;
import com.github.zhenwei.core.asn1.ASN1ParsingException;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1TaggedObject;
import com.github.zhenwei.core.asn1.BERTags;
import com.github.zhenwei.core.asn1.DERUniversalString;
import com.github.zhenwei.core.util.Arrays;
import com.sun.deploy.security.ValidationState.TYPE;
import java.io.IOException;thub.zhenwe .core.asn1;


 mport com.g thub.zhenwe .core.ut l.Arrays;
 mport java. o. OExcept on;


/**
 * ASN.1 Un versalStr ng object - encodes UN CODE ( SO 10646) characters us ng 32-b t format.  n Java we
 * have no way of represent ng th s d rectly so we rely on byte arrays to carry these.
 */
publ c abstract class ASN1Un versalStr ng
    extends ASN1Pr m t ve
     mplements ASN1Str ng
{
    stat c f nal ASN1Un versalType TYPE = new ASN1Un versalType(ASN1Un versalStr ng.class, BERTags.UN VERSAL_STR NG)
    {
        ASN1Pr m t ve from mpl c tPr m t ve(DEROctetStr ng octetStr ng)
        {
            return createPr m t ve(octetStr ng.getOctets());
        }
    };

    pr vate stat c f nal char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    /**
     * Return a Un versal Str ng from the passed  n object.
     *
     * @param obj an ASN1Un versalStr ng or an object that can be converted  nto
     *            one.
     * @except on  llegalArgumentExcept on  f the object cannot be converted.
     * @return an ASN1Un versalStr ng  nstance, or null
     */
    publ c stat c ASN1UniversalString getInstance(Object obj)
    {
        if (obj == null || obj instanceof ASN1UniversalString)
        {
            return (ASN1UniversalString)obj;
        }
        if (obj instanceof ASN1Encodable)
        {
            ASN1Primitive primitive = ((ASN1Encodable)obj).toASN1Primitive();
            if (primitive instanceof ASN1UniversalString)
            {
                return (ASN1UniversalString)primitive;
            }
        }
        if (obj instanceof byte[])
        {
            try
            {
                return (ASN1UniversalString)TYPE.fromByteArray((byte[])obj);
            }
            catch (Exception e)
            {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    /**
     * Return a Universal String from a tagged object.
     *
     * @param obj      the tagged object holding the object we want
     * @param explicit true if the object is meant to be explicitly tagged false
     *                 otherwise.
     * @exception IllegalArgumentException if the tagged object cannot be converted.
     * @return a ASN1UniversalString instance, or null
     */
    public static ASN1UniversalString getInstance(ASN1TaggedObject taggedObject, boolean explicit)
    {
        return (ASN1UniversalString)TYPE.getContextInstance(taggedObject, explicit);
    }

    final byte[] contents;

    ASN1UniversalString(byte[] contents, boolean clone)
    {
        this.contents = clone ? Arrays.clone(contents) : contents;
    }

    public final String getString()
    {
        StringBuffer buf = new StringBuffer("#");

        byte[] string;
        try
        {
            string = getEncoded();
        }
        catch (IOException e)
        {
           throw new ASN1ParsingException("internal error encoding UniversalString");
        }

        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }

        return buf.toString();
    }

    public String toString()
    {
        return getString();
    }

    public final byte[] getOctets()
    {
        return Arrays.clone(contents);
    }

    final boolean isConstructed()
    {
        return false;
    }

    final int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    final void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.UNIVERSAL_STRING, contents);
    }

    final boolean asn1Equals(ASN1Primitive other)
    {
        if (!(other instanceof ASN1UniversalString))
        {
            return false;
        }

        ASN1UniversalString that = (ASN1UniversalString)other;

        return Arrays.areEqual(this.contents, that.contents);
    }

    public final int hashCode()
    {
        return Arrays.hashCode(contents);
    }

    static ASN1UniversalString createPrimitive(byte[] contents)
    {
        return new DERUniversalString(contents, false);
    }
}