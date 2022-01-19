package com.github.zhenwei.sdk.util.asn1.isismtt.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.DirectoryString;

/**
 * Some other restriction regarding the usage of this certificate.
 *
 * <pre>
 *  RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
 * </pre>
 */
public class Restriction
    extends ASN1Object
{
    private DirectoryString restriction;

    public static org.bouncycastle.asn1.isismtt.x509.Restriction getInstance(Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.isismtt.x509.Restriction)
        {
            return (org.bouncycastle.asn1.isismtt.x509.Restriction)obj;
        }

        if (obj != null)
        {
            return new org.bouncycastle.asn1.isismtt.x509.Restriction(DirectoryString.getInstance(obj));
        }

        return null;
    }

    /**
     * Constructor from DirectoryString.
     * <p>
     * The DirectoryString is of type RestrictionSyntax:
     * <pre>
     *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
     * </pre>
     * </p>
     * @param restriction A DirectoryString.
     */
    private Restriction(DirectoryString restriction)
    {
        this.restriction = restriction;
    }

    /**
     * Constructor from a given details.
     *
     * @param restriction The describtion of the restriction.
     */
    public Restriction(String restriction)
    {
        this.restriction = new DirectoryString(restriction);
    }

    public DirectoryString getRestriction()
    {
        return restriction;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <p>
     * Returns:
     * <pre>
     *      RestrictionSyntax ::= DirectoryString (SIZE(1..1024))
     * </pre>
     *
     * @return a DERObject
     */
    public ASN1Primitive toASN1Primitive()
    {
        return restriction.toASN1Primitive();
    }
}