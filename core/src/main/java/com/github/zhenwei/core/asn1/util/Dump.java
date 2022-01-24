package com.github.zhenwei.core.asn1.util;

import java.io.FileInputStream;
import com.github.zhenwei.core.asn1.ASN1InputStream;

/**
 * Command line ASN.1 Dump utility.
 * <p>
 *     Usage: com.github.zhenwei.core.asn1.util.Dump ber_encoded_file
 * </p>
 */
public class Dump
{
    public static void main(
        String args[])
        throws Exception
    {
        FileInputStream fIn = new FileInputStream(args[0]);
        ASN1InputStream bIn = new ASN1InputStream(fIn);
        Object          obj = null;

        while ((obj = bIn.readObject()) != null)
        {
            System.out.println(ASN1Dump.dumpAsString(obj));
        }

        fIn.close();
    }
}