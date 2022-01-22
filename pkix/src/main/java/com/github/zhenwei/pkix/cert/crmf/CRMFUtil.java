package com.github.zhenwei.pkix.cert.crmf;





import ExtensionsGenerator;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.cert.CertIOException;

class CRMFUtil
{
    static void derEncodeToStream(ASN1Object obj, OutputStream stream)
    {
        try
        {
            obj.encodeTo(stream, ASN1Encoding.DER);
            stream.close();
        }
        catch (IOException e)
        {
            throw new CRMFRuntimeException("unable to DER encode object: " + e.getMessage(), e);
        }
    }

    static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value)
        throws CertIOException
    {
        try
        {
            extGenerator.addExtension(oid, isCritical, value);
        }
        catch (IOException e)
        {
            throw new CertIOException("cannot encode extension: " + e.getMessage(), e);
        }
    }
}