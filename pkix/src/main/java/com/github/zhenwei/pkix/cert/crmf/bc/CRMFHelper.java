package com.github.zhenwei.pkix.cert.crmf.bc;


import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.CipherParameters;
import java.security.SecureRandom;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.AlgorithmIdentifierFactory;
import org.bouncycastle.crypto.util.CipherFactory;
import org.bouncycastle.crypto.util.CipherKeyGeneratorFactory;

class CRMFHelper
{
    CRMFHelper()
    {
    }

    CipherKeyGenerator createKeyGenerator(ASN1ObjectIdentifier algorithm, SecureRandom random)
        throws CRMFException
    {
        try
        {
            return CipherKeyGeneratorFactory.createKeyGenerator(algorithm, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }

    static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID)
        throws CRMFException
    {
        try
        {
            return CipherFactory.createContentCipher(forEncryption, encKey, encryptionAlgID);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }

    AlgorithmIdentifier generateEncryptionAlgID(ASN1ObjectIdentifier encryptionOID, KeyParameter encKey, SecureRandom random)
        throws CRMFException
    {
        try
        {
            return AlgorithmIdentifierFactory.generateEncryptionAlgID(encryptionOID, encKey.getKey().length * 8, random);
        }
        catch (IllegalArgumentException e)
        {
            throw new CRMFException(e.getMessage(), e);
        }
    }
}