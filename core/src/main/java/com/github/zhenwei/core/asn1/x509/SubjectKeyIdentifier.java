package com.github.zhenwei.core.asn1.x509;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.Arrays;

/**
 * The SubjectKeyIdentifier object.
 * <pre>
 * SubjectKeyIdentifier::= OCTET STRING
 * </pre>
 */
public class SubjectKeyIdentifier
    extends ASN1Object
{
    private byte[] keyidentifier;

    public static org.bouncycastle.asn1.x509.SubjectKeyIdentifier getInstance(
        ASN1TaggedObject obj,
        boolean          explicit)
    {
        return getInstance(ASN1OctetString.getInstance(obj, explicit));
    }

    public static org.bouncycastle.asn1.x509.SubjectKeyIdentifier getInstance(
        Object obj)
    {
        if (obj instanceof org.bouncycastle.asn1.x509.SubjectKeyIdentifier)
        {
            return (org.bouncycastle.asn1.x509.SubjectKeyIdentifier)obj;
        }
        else if (obj != null)
        {
            return new org.bouncycastle.asn1.x509.SubjectKeyIdentifier(ASN1OctetString.getInstance(obj));
        }

        return null;
    }

    public static org.bouncycastle.asn1.x509.SubjectKeyIdentifier fromExtensions(Extensions extensions)
    {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.subjectKeyIdentifier));
    }

    public SubjectKeyIdentifier(
        byte[] keyid)
    {
        this.keyidentifier = Arrays.clone(keyid);
    }

    protected SubjectKeyIdentifier(
        ASN1OctetString keyid)
    {
        this(keyid.getOctets());
    }

    public byte[] getKeyIdentifier()
    {
        return Arrays.clone(keyidentifier);
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(getKeyIdentifier());
    }
}