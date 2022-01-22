package com.github.zhenwei.pkix.cms.jcajce;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cms.CMSException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
 

public class JceAlgorithmIdentifierConverter
{
    private EnvelopedDataHelper helper = new EnvelopedDataHelper(new DefaultJcaJceExtHelper());
    private SecureRandom random;

    public JceAlgorithmIdentifierConverter()
    {
    }

    public jcajce.JceAlgorithmIdentifierConverter setProvider(Provider provider)
    {
        this.helper = new EnvelopedDataHelper(new ProviderJcaJceExtHelper(provider));

        return this;
    }

    public jcajce.JceAlgorithmIdentifierConverter setProvider(String providerName)
    {
        this.helper = new EnvelopedDataHelper(new NamedJcaJceExtHelper(providerName));

        return this;
    }

    public AlgorithmParameters getAlgorithmParameters(AlgorithmIdentifier algorithmIdentifier)
        throws CMSException
    {
        ASN1Encodable parameters = algorithmIdentifier.getParameters();

        if (parameters == null)
        {
            return null;
        }

        try
        {
            AlgorithmParameters params = helper.createAlgorithmParameters(algorithmIdentifier.getAlgorithm());

            CMSUtils.loadParameters(params, algorithmIdentifier.getParameters());

            return params;
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new CMSException("can't find parameters for algorithm", e);
        }
        catch (NoSuchProviderException e)
        {
            throw new CMSException("can't find provider for algorithm", e);
        }
    }
}