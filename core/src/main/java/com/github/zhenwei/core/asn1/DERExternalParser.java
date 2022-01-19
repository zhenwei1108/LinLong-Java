package com.github.zhenwei.core.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Exception;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DLExternal;

/**
 * Parser DER EXTERNAL tagged objects.
 */
public class DERExternalParser
    implements ASN1ExternalParser
{
    private ASN1StreamParser _parser;

    /**
     * Base constructor.
     *
     * @param parser the underlying parser to read the DER EXTERNAL from.
     */
    public DERExternalParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    public ASN1Encodable readObject()
        throws IOException
    {
        return _parser.readObject();
    }

    /**
     * Return an in-memory, encodable, representation of the EXTERNAL object.
     *
     * @return a DERExternal.
     * @throws IOException if there is an issue loading the data.
     */
    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return parse(_parser);
    }

    /**
     * Return an DERExternal representing this parser and its contents.
     *
     * @return an DERExternal
     */
    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException ioe)
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
        catch (IllegalArgumentException ioe)
        {
            throw new ASN1ParsingException("unable to get DER object", ioe);
        }
    }

    static DLExternal parse(ASN1StreamParser sp) throws IOException
    {
        try
        {
            return new DLExternal(sp.readVector());
        }
        catch (IllegalArgumentException e)
        {
            throw new ASN1Exception(e.getMessage(), e);
        }
    }
}