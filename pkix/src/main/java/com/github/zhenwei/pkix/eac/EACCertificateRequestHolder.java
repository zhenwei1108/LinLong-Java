package com.github.zhenwei.pkix.eac;


 
import  CVCertificateRequest;
import  PublicKeyDataObject;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.eac.operator.EACSignatureVerifier;

public class EACCertificateRequestHolder
{
    private CVCertificateRequest request;

    private static CVCertificateRequest parseBytes(byte[] requestEncoding)
        throws IOException
    {
        try
        {
            return CVCertificateRequest.getInstance(requestEncoding);
        }
        catch (ClassCastException e)
        {
            throw new EACIOException("malformed data: " + e.getMessage(), e);
        }
        catch (IllegalArgumentException e)
        {
            throw new EACIOException("malformed data: " + e.getMessage(), e);
        }
        catch (ASN1ParsingException e)
        {
            if (e.getCause() instanceof IOException)
            {
                throw (IOException)e.getCause();
            }
            else
            {
                throw new EACIOException("malformed data: " + e.getMessage(), e);
            }
        }
    }

    public EACCertificateRequestHolder(byte[] certEncoding)
        throws IOException
    {
        this(parseBytes(certEncoding));
    }

    public EACCertificateRequestHolder(CVCertificateRequest request)
    {
        this.request = request;
    }

    /**
     * Return the underlying ASN.1 structure for the certificate in this holder.
     *
     * @return a X509CertificateStructure object.
     */
    public CVCertificateRequest toASN1Structure()
    {
        return request;
    }

    public PublicKeyDataObject getPublicKeyDataObject()
    {
        return request.getPublicKey();
    }

    public boolean isInnerSignatureValid(EACSignatureVerifier verifier)
        throws EACException
    {
        try
        {
            OutputStream vOut = verifier.getOutputStream();

            vOut.write(request.getCertificateBody().getEncoded(ASN1Encoding.DER));

            vOut.close();

            return verifier.verify(request.getInnerSignature());
        }
        catch (Exception e)
        {
            throw new EACException("unable to process signature: " + e.getMessage(), e);
        }
    }
}