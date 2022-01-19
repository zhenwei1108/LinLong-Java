package com.github.zhenwei.core.asn1;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERApplicationSpecificParser;
import org.bouncycastle.asn1.BEROctetStringParser;
import org.bouncycastle.asn1.BERSequenceParser;
import org.bouncycastle.asn1.BERSetParser;
import org.bouncycastle.asn1.BERTaggedObjectParser;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERExternalParser;
import org.bouncycastle.asn1.DEROctetStringParser;
import org.bouncycastle.asn1.DLApplicationSpecific;
import org.bouncycastle.asn1.DLSequenceParser;
import org.bouncycastle.asn1.DLSetParser;
import org.bouncycastle.asn1.InMemoryRepresentable;

/**
 * A parser for ASN.1 streams which also returns, where possible, parsers for the objects it encounters.
 */
public class ASN1StreamParser
{
    private final InputStream _in;
    private final int _limit;
    private final byte[][] tmpBuffers;

    public ASN1StreamParser(InputStream in)
    {
        this(in, StreamUtil.findLimit(in));
    }

    public ASN1StreamParser(byte[] encoding)
    {
        this(new ByteArrayInputStream(encoding), encoding.length);
    }

    public ASN1StreamParser(InputStream in, int limit)
    {
        this(in, limit, new byte[11][]);
    }

    ASN1StreamParser(InputStream in, int limit, byte[][] tmpBuffers)
    {
        this._in = in;
        this._limit = limit;
        this.tmpBuffers = tmpBuffers;
    }

    ASN1Encodable readIndef(int tagValue) throws IOException
    {
        // Note: INDEF => CONSTRUCTED

        switch (tagValue)
        {
        case BERTags.BIT_STRING:
            return new BERBitStringParser(this);
        case BERTags.OCTET_STRING:
            return new BEROctetStringParser(this);
        case BERTags.EXTERNAL:
            return new DERExternalParser(this);
        case BERTags.SEQUENCE:
            return new BERSequenceParser(this);
        case BERTags.SET:
            return new BERSetParser(this);
        default:
            throw new ASN1Exception("unknown BER object encountered: 0x" + Integer.toHexString(tagValue));
        }
    }

    ASN1Encodable readImplicit(boolean constructed, int tag) throws IOException
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            if (!constructed)
            {
                throw new IOException("indefinite-length primitive encoding encountered");
            }

            return readIndef(tag);
        }

        if (constructed)
        {
            switch (tag)
            {
            case BERTags.BIT_STRING:
                return new BERBitStringParser(this);
            case BERTags.OCTET_STRING:
                return new BEROctetStringParser(this);
            case BERTags.SET:
                return new DLSetParser(this);
            case BERTags.SEQUENCE:
                return new DLSequenceParser(this);
            }
        }
        else
        {
            switch (tag)
            {
            case BERTags.BIT_STRING:
                return new DLBitStringParser((DefiniteLengthInputStream)_in);
            case BERTags.OCTET_STRING:
                return new DEROctetStringParser((DefiniteLengthInputStream)_in);
            case BERTags.SET:
                throw new ASN1Exception("sequences must use constructed encoding (see X.690 8.9.1/8.10.1)");
            case BERTags.SEQUENCE:
                throw new ASN1Exception("sets must use constructed encoding (see X.690 8.11.1/8.12.1)");
            }
        }

        throw new ASN1Exception("implicit tagging not implemented");
    }

    ASN1Primitive readTaggedObject(int tagClass, int tagNo, boolean constructed) throws IOException
    {
        if (!constructed)
        {
            byte[] contentsOctets = ((DefiniteLengthInputStream) _in).toByteArray();
            return ASN1TaggedObject.createPrimitive(tagClass, tagNo, contentsOctets);
        }

        boolean isIL = (_in instanceof IndefiniteLengthInputStream);
        ASN1EncodableVector contentsElements = readVector();
        return ASN1TaggedObject.createConstructed(tagClass, tagNo, isIL, contentsElements);
    }

    public ASN1Encodable readObject()
        throws IOException
    {
        int tag = _in.read();
        if (tag == -1)
        {
            return null;
        }

        //
        // turn of looking for "00" while we resolve the tag
        //
        set00Check(false);

        //
        // calculate tag number
        //
        int tagNo = ASN1InputStream.readTagNumber(_in, tag);

        boolean isConstructed = (tag & BERTags.CONSTRUCTED) != 0;

        //
        // calculate length
        //
        int length = ASN1InputStream.readLength(_in, _limit,
            tagNo == BERTags.BIT_STRING || tagNo == BERTags.OCTET_STRING || tagNo == BERTags.SEQUENCE
                || tagNo == BERTags.SET || tagNo == BERTags.EXTERNAL);

        if (length < 0) // indefinite-length method
        {
            if (!isConstructed)
            {
                throw new IOException("indefinite-length primitive encoding encountered");
            }

            IndefiniteLengthInputStream indIn = new IndefiniteLengthInputStream(_in, _limit);
            org.bouncycastle.asn1.ASN1StreamParser sp = new org.bouncycastle.asn1.ASN1StreamParser(indIn, _limit, tmpBuffers);

            int tagClass = tag & BERTags.PRIVATE;
            if (0 != tagClass)
            {
                if (BERTags.APPLICATION == tagClass)
                {
                    return new BERApplicationSpecificParser(tagNo, true, sp);
                }

                return new BERTaggedObjectParser(tagClass, tagNo, true, sp);
            }

            return sp.readIndef(tagNo);
        }
        else
        {
            DefiniteLengthInputStream defIn = new DefiniteLengthInputStream(_in, length, _limit);

            int tagClass = tag & BERTags.PRIVATE;
            if (0 != tagClass)
            {
                org.bouncycastle.asn1.ASN1StreamParser sp = new org.bouncycastle.asn1.ASN1StreamParser(defIn, defIn.getLimit(), tmpBuffers);

                // TODO Special handling can be removed once ASN1ApplicationSpecific types removed.
                if (BERTags.APPLICATION == tagClass)
                {
                    // This cast is ensuring the current user-expected return type.
                    return (DLApplicationSpecific)sp.readTaggedObject(tagClass, tagNo, isConstructed);
                }

                return new BERTaggedObjectParser(tagClass, tagNo, isConstructed, sp);
            }

            if (!isConstructed)
            {
                // Some primitive encodings can be handled by parsers too...
                switch (tagNo)
                {
                case BERTags.BIT_STRING:
                    return new DLBitStringParser(defIn);
                case BERTags.OCTET_STRING:
                    return new DEROctetStringParser(defIn);
                }

                try
                {
                    return ASN1InputStream.createPrimitiveDERObject(tagNo, defIn, tmpBuffers);
                }
                catch (IllegalArgumentException e)
                {
                    throw new ASN1Exception("corrupted stream detected", e);
                }
            }

            org.bouncycastle.asn1.ASN1StreamParser sp = new org.bouncycastle.asn1.ASN1StreamParser(defIn, defIn.getLimit(), tmpBuffers);

            switch (tagNo)
            {
            case BERTags.BIT_STRING:
                return new BERBitStringParser(sp);
            case BERTags.OCTET_STRING:
                //
                // yes, people actually do this...
                //
                return new BEROctetStringParser(sp);
            case BERTags.SEQUENCE:
                return new DLSequenceParser(sp);
            case BERTags.SET:
                return new DLSetParser(sp);
            case BERTags.EXTERNAL:
                return new DERExternalParser(sp);
            default:
                throw new IOException("unknown tag " + tagNo + " encountered");
            }
        }
    }

    private void set00Check(boolean enabled)
    {
        if (_in instanceof IndefiniteLengthInputStream)
        {
            ((IndefiniteLengthInputStream)_in).setEofOn00(enabled);
        }
    }

    ASN1EncodableVector readVector() throws IOException
    {
        ASN1Encodable obj = readObject();
        if (null == obj)
        {
            return new ASN1EncodableVector(0);
        }

        ASN1EncodableVector v = new ASN1EncodableVector();
        do
        {
            if (obj instanceof InMemoryRepresentable)
            {
                v.add(((InMemoryRepresentable)obj).getLoadedObject());
            }
            else
            {
                v.add(obj.toASN1Primitive());
            }
        }
        while ((obj = readObject()) != null);
        return v;
    }
}