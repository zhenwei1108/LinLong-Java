package com.github.zhenwei.provider.x509;

import java.io.InputStream;
import java.util.Collection;
import com.github.zhenwei.provider.x509.util.StreamParsingException;

/**
 * This abstract class defines the service provider interface (SPI) for
 * X509StreamParser.
 *
 * @see com.github.zhenwei.provider.x509.X509StreamParser
 *
 */
public abstract class X509StreamParserSpi
{
    /**
     * Initializes this stream parser with the input stream.
     *
     * @param in The input stream.
     */
    public abstract void engineInit(InputStream in);

    /**
     * Returns the next X.509 object of the type of this SPI from the given
     * input stream.
     *
     * @return the next X.509 object in the stream or <code>null</code> if the
     *         end of the stream is reached.
     * @exception StreamParsingException
     *                if the object cannot be created from input stream.
     */
    public abstract Object engineRead() throws StreamParsingException;

    /**
     * Returns all X.509 objects of the type of this SPI from
     * the given input stream.
     *
     * @return A collection of all X.509 objects in the input stream or
     *         <code>null</code> if the end of the stream is reached.
     * @exception StreamParsingException
     *                if an object cannot be created from input stream.
     */
    public abstract Collection engineReadAll() throws StreamParsingException;
}