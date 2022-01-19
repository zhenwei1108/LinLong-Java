package com.github.zhenwei.core.asn1;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.BERTags;

/**
 * An ASN.1 DER NULL object.
 * <p>
 * Preferably use the constant:  DERNull.INSTANCE.
 */
public class DERNull
    extends ASN1Null
{
    public static final org.bouncycastle.asn1.DERNull INSTANCE = new org.bouncycastle.asn1.DERNull();

    private static final byte[]  zeroBytes = new byte[0];

    private DERNull()
    {
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, 0);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.NULL, zeroBytes);
    }
}