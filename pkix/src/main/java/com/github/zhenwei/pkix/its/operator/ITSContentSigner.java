package com.github.zhenwei.pkix.its.operator;



import java.io.OutputStream;
import org.bouncycastle.its.ITSCertificate;

public interface ITSContentSigner
{
    /**
     * Returns a stream that will accept data for the purpose of calculating
     * a signature. Use  io.TeeOutputStream if you want to accumulate
     * the data on the fly as well.
     *
     * @return an OutputStream
     */
    OutputStream getOutputStream();

    /**
     * Returns a signature based on the current data written to the stream, since the
     * start or the last call to getSignature().
     *
     * @return bytes representing the signature.
     */
    byte[] getSignature();

    ITSCertificate getAssociatedCertificate();

    byte[] getAssociatedCertificateDigest();

    AlgorithmIdentifier getDigestAlgorithm();

    /**
     * Return true if this ContentSigner is for self signing. False otherwise.
     *
     * @return true if for self-signing.
     */
    boolean isForSelfSigning();
}