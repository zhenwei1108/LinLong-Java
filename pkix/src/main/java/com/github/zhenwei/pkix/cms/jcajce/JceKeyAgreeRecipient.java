package com.github.zhenwei.pkix.cms.jcajce;


import Gost2814789EncryptedKey;
import Gost2814789KeyWrapParameters;
import KeyAgreeRecipient;
import cms.ecc.ECCCMSSharedInfo;
import cms.ecc.MQVuserKeyingMaterial;
import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.pkix.cms.CMSException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
  
import org.bouncycastle.jcajce.spec.MQVParameterSpec;
import org.bouncycastle.jcajce.spec.UserKeyingMaterialSpec;
import org.bouncycastle.operator.DefaultSecretKeySizeProvider;
import org.bouncycastle.operator.SecretKeySizeProvider;


 


public abstract class JceKeyAgreeRecipient
    implements KeyAgreeRecipient
{
    private static final Set possibleOldMessages = new HashSet();

    static
    {
        possibleOldMessages.add(X9ObjectIdentifiers.dhSinglePass_stdDH_sha1kdf_scheme);
        possibleOldMessages.add(X9ObjectIdentifiers.mqvSinglePass_sha1kdf_scheme);
    }

    private PrivateKey recipientKey;
    protected EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    protected EnvelopedDataHelper contentHelper = helper;
    private SecretKeySizeProvider keySizeProvider = new DefaultSecretKeySizeProvider();
    private AlgorithmIdentifier privKeyAlgID = null;

    public JceKeyAgreeRecipient(PrivateKey recipientKey)
    {
        this.recipientKey = CMSUtils.cleanPrivateKey(recipientKey);
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param provider provider to use.
     * @return this recipient.
     */
    public jcajce.JceKeyAgreeRecipient setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Set the provider to use for key recovery and content processing.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public jcajce.JceKeyAgreeRecipient setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));
        this.contentHelper = helper;

        return this;
    }

    /**
     * Set the provider to use for content processing.  If providerName is null a "no provider" search will be
     *  used to satisfy getInstance calls.
     *
     * @param provider the provider to use.
     * @return this recipient.
     */
    public jcajce.JceKeyAgreeRecipient setContentProvider(Provider provider)
    {
        this.contentHelper = CMSUtils.createContentHelper(provider);

        return this;
    }

    /**
     * Set the provider to use for content processing. If providerName is null a "no provider" search will be
     * used to satisfy getInstance calls.
     *
     * @param providerName the name of the provider to use.
     * @return this recipient.
     */
    public jcajce.JceKeyAgreeRecipient setContentProvider(String providerName)
    {
        this.contentHelper = CMSUtils.createContentHelper(providerName);

        return this;
    }

    /**
     * Set the algorithm identifier for the private key. You'll want to use this if you are
     * dealing with a HSM and it is not possible to get the encoding of the private key.
     *
     * @param privKeyAlgID the algorithm identifier for the private key.
     * @return this recipient.
     */
    public jcajce.JceKeyAgreeRecipient setPrivateKeyAlgorithmIdentifier(AlgorithmIdentifier privKeyAlgID)
    {
        this.privKeyAlgID = privKeyAlgID;

        return this;
    }

    private SecretKey calculateAgreedWrapKey(AlgorithmIdentifier keyEncAlg, AlgorithmIdentifier wrapAlg,
        PublicKey senderPublicKey, ASN1OctetString userKeyingMaterial, PrivateKey receiverPrivateKey, KeyMaterialGenerator kmGen)
        throws CMSException, GeneralSecurityException, IOException
    {
        receiverPrivateKey = CMSUtils.cleanPrivateKey(receiverPrivateKey);

        if (CMSUtils.isMQV(keyEncAlg.getAlgorithm()))
        {
            MQVuserKeyingMaterial ukm = MQVuserKeyingMaterial.getInstance(userKeyingMaterial.getOctets());

            SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(
                                                getPrivateKeyAlgorithmIdentifier(),
                                                ukm.getEphemeralPublicKey().getPublicKey().getBytes());

            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubInfo.getEncoded());
            KeyFactory fact = helper.createKeyFactory(keyEncAlg.getAlgorithm());
            PublicKey ephemeralKey = fact.generatePublic(pubSpec);

            KeyAgreement agreement = helper.createKeyAgreement(keyEncAlg.getAlgorithm());

            byte[] ukmKeyingMaterial = (ukm.getAddedukm() != null) ? ukm.getAddedukm().getOctets() : null;
            if (kmGen == old_ecc_cms_Generator)
            {
                ukmKeyingMaterial = old_ecc_cms_Generator.generateKDFMaterial(wrapAlg, keySizeProvider.getKeySize(wrapAlg), ukmKeyingMaterial);
            }

            agreement.init(receiverPrivateKey, new MQVParameterSpec(receiverPrivateKey, ephemeralKey, ukmKeyingMaterial));
            agreement.doPhase(senderPublicKey, true);

            return agreement.generateSecret(wrapAlg.getAlgorithm().getId());
        }
        else
        {
            KeyAgreement agreement = helper.createKeyAgreement(keyEncAlg.getAlgorithm());

            UserKeyingMaterialSpec userKeyingMaterialSpec = null;

            if (CMSUtils.isEC(keyEncAlg.getAlgorithm()))
            {
                if (userKeyingMaterial != null)
                {
                    byte[] ukmKeyingMaterial = kmGen.generateKDFMaterial(wrapAlg, keySizeProvider.getKeySize(wrapAlg), userKeyingMaterial.getOctets());

                    userKeyingMaterialSpec = new UserKeyingMaterialSpec(ukmKeyingMaterial);
                }
                else
                {
                    byte[] ukmKeyingMaterial = kmGen.generateKDFMaterial(wrapAlg, keySizeProvider.getKeySize(wrapAlg), null);

                    userKeyingMaterialSpec = new UserKeyingMaterialSpec(ukmKeyingMaterial);
                }
            }
            else if (CMSUtils.isRFC2631(keyEncAlg.getAlgorithm()))
            {
                if (userKeyingMaterial != null)
                {
                    userKeyingMaterialSpec = new UserKeyingMaterialSpec(userKeyingMaterial.getOctets());
                }
            }
            else if (CMSUtils.isGOST(keyEncAlg.getAlgorithm()))
            {
                if (userKeyingMaterial != null)
                {
                    userKeyingMaterialSpec = new UserKeyingMaterialSpec(userKeyingMaterial.getOctets());
                }
            }
            else
            {
                throw new CMSException("Unknown key agreement algorithm: " + keyEncAlg.getAlgorithm());
            }

            agreement.init(receiverPrivateKey, userKeyingMaterialSpec);

            agreement.doPhase(senderPublicKey, true);

            return agreement.generateSecret(wrapAlg.getAlgorithm().getId());
        }
    }

    protected Key unwrapSessionKey(ASN1ObjectIdentifier wrapAlg, SecretKey agreedKey, ASN1ObjectIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException, InvalidKeyException, NoSuchAlgorithmException
    {
        Cipher keyCipher = helper.createCipher(wrapAlg);
        keyCipher.init(Cipher.UNWRAP_MODE, agreedKey);
        return keyCipher.unwrap(encryptedContentEncryptionKey, helper.getBaseCipherName(contentEncryptionAlgorithm), Cipher.SECRET_KEY);
    }

    protected Key extractSecretKey(AlgorithmIdentifier keyEncryptionAlgorithm, AlgorithmIdentifier contentEncryptionAlgorithm, SubjectPublicKeyInfo senderKey, ASN1OctetString userKeyingMaterial, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        try
        {
            AlgorithmIdentifier wrapAlg =
                AlgorithmIdentifier.getInstance(keyEncryptionAlgorithm.getParameters());

            X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(senderKey.getEncoded());
            KeyFactory fact = helper.createKeyFactory(senderKey.getAlgorithm().getAlgorithm());
            PublicKey senderPublicKey = fact.generatePublic(pubSpec);

            try
            {
                SecretKey agreedWrapKey = calculateAgreedWrapKey(keyEncryptionAlgorithm, wrapAlg,
                    senderPublicKey, userKeyingMaterial, recipientKey, ecc_cms_Generator);

                if (wrapAlg.getAlgorithm().equals(CryptoProObjectIdentifiers.id_Gost28147_89_None_KeyWrap)
                    || wrapAlg.getAlgorithm().equals(CryptoProObjectIdentifiers.id_Gost28147_89_CryptoPro_KeyWrap))
                {
                    Gost2814789EncryptedKey encKey = Gost2814789EncryptedKey.getInstance(encryptedContentEncryptionKey);
                    Gost2814789KeyWrapParameters wrapParams = Gost2814789KeyWrapParameters.getInstance(wrapAlg.getParameters());
             
                    Cipher keyCipher = helper.createCipher(wrapAlg.getAlgorithm());

                    keyCipher.init(Cipher.UNWRAP_MODE, agreedWrapKey, new GOST28147WrapParameterSpec(wrapParams.getEncryptionParamSet(), userKeyingMaterial.getOctets()));

                    return keyCipher.unwrap(Arrays.concatenate(encKey.getEncryptedKey(), encKey.getMacKey()), helper.getBaseCipherName(contentEncryptionAlgorithm.getAlgorithm()), Cipher.SECRET_KEY);
                }

                return unwrapSessionKey(wrapAlg.getAlgorithm(), agreedWrapKey, contentEncryptionAlgorithm.getAlgorithm(), encryptedContentEncryptionKey);
            }
            catch (InvalidKeyException e)
            {
                // might be a pre-RFC 5753 message
                if (possibleOldMessages.contains(keyEncryptionAlgorithm.getAlgorithm()))
                {
                    SecretKey agreedWrapKey = calculateAgreedWrapKey(keyEncryptionAlgorithm, wrapAlg,
                        senderPublicKey, userKeyingMaterial, recipientKey, old_ecc_cms_Generator);

                    return unwrapSessionKey(wrapAlg.getAlgorithm(), agreedWrapKey, contentEncryptionAlgorithm.getAlgorithm(), encryptedContentEncryptionKey);
                }
                // one last try - people do actually do this it turns out
                if (userKeyingMaterial != null)
                {
                    try
                    {
                        SecretKey agreedWrapKey = calculateAgreedWrapKey(keyEncryptionAlgorithm, wrapAlg,
                            senderPublicKey, userKeyingMaterial, recipientKey, simple_ecc_cmsGenerator);

                        return unwrapSessionKey(wrapAlg.getAlgorithm(), agreedWrapKey, contentEncryptionAlgorithm.getAlgorithm(), encryptedContentEncryptionKey);
                    }
                    catch (InvalidKeyException ex)
                    {
                        throw e; // we'll throw the original exception
                    }
                }
                throw e;
            }
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find algorithm.", e);
        }
        catch (InvalidKeyException e)
        {
            throw new CMSException("key invalid in message.", e);
        }
        catch (InvalidKeySpecException e)
        {
            throw new CMSException("originator key spec invalid.", e);
        }
        catch (NoSuchPaddingException e)
        {
            throw new CMSException("required padding not supported.", e);
        }
        catch (Exception e)
        {
            throw new CMSException("originator key invalid.", e);
        }
    }

    public AlgorithmIdentifier getPrivateKeyAlgorithmIdentifier()
    {
        if (privKeyAlgID == null)
        {
            privKeyAlgID = PrivateKeyInfo.getInstance(recipientKey.getEncoded()).getPrivateKeyAlgorithm();
        }

        return privKeyAlgID;
    }

    private static KeyMaterialGenerator old_ecc_cms_Generator = new KeyMaterialGenerator()
    {
        public byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters)
        {
            ECCCMSSharedInfo eccInfo;

            // this isn't correct with AES and RFC 5753, but we have messages predating it...
            eccInfo = new ECCCMSSharedInfo(new AlgorithmIdentifier(keyAlgorithm.getAlgorithm(), DERNull.INSTANCE), userKeyMaterialParameters, Pack.intToBigEndian(keySize));

            try
            {
                return eccInfo.getEncoded(ASN1Encoding.DER);
            }
            catch (IOException e)
            {
                throw new IllegalStateException("Unable to create KDF material: " + e);
            }
        }
    };

    private static KeyMaterialGenerator simple_ecc_cmsGenerator = new KeyMaterialGenerator()
    {
        public byte[] generateKDFMaterial(AlgorithmIdentifier keyAlgorithm, int keySize, byte[] userKeyMaterialParameters)
        {
            return userKeyMaterialParameters;
        }
    };
    
    private static KeyMaterialGenerator ecc_cms_Generator = new RFC5753KeyMaterialGenerator();
}