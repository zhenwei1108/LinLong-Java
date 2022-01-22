package com.github.zhenwei.pkix.cert.ocsp;


import X500Name;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import java.io.OutputStream;
import ocsp.ResponderID;
import org.bouncycastle.operator.DigestCalculator;

/**
 * Carrier for a ResponderID.
 */
public class RespID
{
    public static final AlgorithmIdentifier HASH_SHA1 = new AlgorithmIdentifier(
        OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);

    ResponderID id;

    public RespID(
        ResponderID id)
    {
        this.id = id;
    }

    public RespID(
        X500Name name)
    {
        this.id = new ResponderID(name);
    }

    /**
     * Calculate a RespID based on the public key of the responder.
     *
     * @param subjectPublicKeyInfo the info structure for the responder public key.
     * @param digCalc a SHA-1 digest calculator.
     * @throws OCSPException on exception creating ID.
     */
    public RespID(
        SubjectPublicKeyInfo subjectPublicKeyInfo,
        DigestCalculator         digCalc)
        throws OCSPException
    {
        try
        {
            if (!digCalc.getAlgorithmIdentifier().equals(HASH_SHA1))
            {
                throw new IllegalArgumentException("only SHA-1 can be used with RespID - found: " + digCalc.getAlgorithmIdentifier().getAlgorithm());
            }

            OutputStream     digOut = digCalc.getOutputStream();

            digOut.write(subjectPublicKeyInfo.getPublicKeyData().getBytes());
            digOut.close();

            this.id = new ResponderID(new DEROctetString(digCalc.getDigest()));
        }
        catch (Exception e)
        {
            throw new OCSPException("problem creating ID: " + e, e);
        }
    }

    public ResponderID toASN1Primitive()
    {
        return id;
    }

    public boolean equals(
        Object  o)
    {
        if (!(o instanceof org.bouncycastle.cert.ocsp.RespID))
        {
            return false;
        }

        org.bouncycastle.cert.ocsp.RespID obj = (org.bouncycastle.cert.ocsp.RespID)o;

        return id.equals(obj.id);
    }

    public int hashCode()
    {
        return id.hashCode();
    }
}