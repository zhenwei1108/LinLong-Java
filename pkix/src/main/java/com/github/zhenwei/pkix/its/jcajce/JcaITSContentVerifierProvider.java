package com.github.zhenwei.pkix.its.jcajce;


import com.github.zhenwei.core.asn1.nist.NISTObjectIdentifiers;
 
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.pkix.operator.ContentVerifier;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.provider.jcajce.util.DefaultJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.JcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.NamedJcaJceHelper;
import com.github.zhenwei.provider.jcajce.util.ProviderJcaJceHelper;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Provider;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import org.bouncycastle.its.ITSCertificate;
import org.bouncycastle.its.operator.ITSContentVerifierProvider;
import org.bouncycastle.oer.OEREncoder;
import org.bouncycastle.oer.its.PublicVerificationKey;
import org.bouncycastle.oer.its.ToBeSignedCertificate;
import org.bouncycastle.oer.its.VerificationKeyIndicator;
import org.bouncycastle.oer.its.template.IEEE1609dot2;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;


public class JcaITSContentVerifierProvider
    implements ITSContentVerifierProvider
{
    public static class Builder
    {
        private JcaJceHelper helper = new DefaultJcaJceHelper();

        public Builder setProvider(Provider provider)
        {
            this.helper = new ProviderJcaJceHelper(provider);

            return this;
        }

        public Builder setProvider(String providerName)
        {
            this.helper = new NamedJcaJceHelper(providerName);

            return this;
        }

        public JcaITSContentVerifierProvider build(ITSCertificate issuer)
        {
            return new JcaITSContentVerifierProvider(issuer, helper);
        }
    }

    private final ITSCertificate issuer;
    private final byte[] parentData;
    private final AlgorithmIdentifier digestAlgo;
    private final ECPublicKey pubParams;
    private final int sigChoice;
    private JcaJceHelper helper;

    private JcaITSContentVerifierProvider(ITSCertificate issuer, JcaJceHelper helper)
    {
        this.issuer = issuer;
        this.helper = helper;
        try
        {
            this.parentData = issuer.getEncoded();
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to extract parent data: " + e.getMessage());
        }
        ToBeSignedCertificate toBeSignedCertificate =
            issuer.toASN1Structure().getCertificateBase().getToBeSignedCertificate();
        VerificationKeyIndicator vki = toBeSignedCertificate.getVerificationKeyIndicator();

        if (vki.getObject() instanceof PublicVerificationKey)
        {
            PublicVerificationKey pvi = PublicVerificationKey.getInstance(vki.getObject());
            sigChoice = pvi.getChoice();
            switch (pvi.getChoice())
            {
            case PublicVerificationKey.ecdsaNistP256:
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                break;
            case PublicVerificationKey.ecdsaBrainpoolP256r1:
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
                break;
            case PublicVerificationKey.ecdsaBrainpoolP384r1:
                digestAlgo = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha384);
                break;
            default:
                throw new IllegalArgumentException("unknown key type");
            }

            pubParams = (ECPublicKey)new JcaITSPublicVerificationKey(pvi, helper).getKey();
        }
        else
        {
            throw new IllegalArgumentException("not public verification key");
        }
    }

    @Override
    public boolean hasAssociatedCertificate()
    {
        return issuer != null;
    }

    @Override
    public ITSCertificate getAssociatedCertificate()
    {
        return issuer;
    }

    @Override
    public ContentVerifier get(int verifierAlgorithmIdentifier)
        throws OperatorCreationException
    {
        if (sigChoice != verifierAlgorithmIdentifier)
        {
            throw new OperatorCreationException("wrong verifier for algorithm: " + verifierAlgorithmIdentifier);
        }

        DigestCalculatorProvider digestCalculatorProvider;

        try
        {
            JcaDigestCalculatorProviderBuilder bld = new JcaDigestCalculatorProviderBuilder().setHelper(helper);
            digestCalculatorProvider = bld.build();
        }
        catch (Exception ex)
        {
            throw new IllegalStateException(ex.getMessage(), ex);
        }

        final DigestCalculator calculator = digestCalculatorProvider.get(digestAlgo);
        try
        {
            final OutputStream os = calculator.getOutputStream();
            os.write(parentData, 0, parentData.length);
            final byte[] parentDigest = calculator.getDigest();

            final byte[] parentTBSDigest;

            if (issuer.getIssuer().isSelf())
            {
                byte[] enc = OEREncoder.toByteArray(issuer.toASN1Structure().getCertificateBase().getToBeSignedCertificate(), IEEE1609dot2.tbsCertificate);
                os.write(enc, 0, enc.length);
                parentTBSDigest = calculator.getDigest();
            }
            else
            {
                parentTBSDigest = null;
            }

            final Signature signature;
            switch (this.sigChoice)
            {
            case PublicVerificationKey.ecdsaNistP256:
            case PublicVerificationKey.ecdsaBrainpoolP256r1:
                signature = helper.createSignature("SHA256withECDSA");
                break;
            case PublicVerificationKey.ecdsaBrainpoolP384r1:
                signature = helper.createSignature("SHA384withECDSA");
                break;
            default:
                throw new IllegalArgumentException("choice " + this.sigChoice + " not supported");
            }

            return new ContentVerifier()
            {
                @Override
                public AlgorithmIdentifier getAlgorithmIdentifier()
                {
                    return null;
                }

                @Override
                public OutputStream getOutputStream()
                {
                    return os;
                }

                @Override
                public boolean verify(byte[] expected)
                {
                    byte[] clientCertDigest = calculator.getDigest();
                    try
                    {
                        signature.initVerify(pubParams);
                        signature.update(clientCertDigest);

                        if (parentTBSDigest != null && Arrays.areEqual(clientCertDigest, parentTBSDigest))
                        {
                            byte[] empty = calculator.getDigest();
                            signature.update(empty);
                        }
                        else
                        {
                            signature.update(parentDigest);
                        }

                        return signature.verify(expected);
                    }
                    catch (Exception ex)
                    {
                        throw new RuntimeException(ex.getMessage(), ex);
                    }

                }
            };
        }
        catch (Exception ex)
        {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }
}