package com.github.zhenwei.pkix.pkcs;


import com.github.zhenwei.core.asn1.pkcs.MacData;
import com.github.zhenwei.core.asn1.pkcs.PKCS12PBEParams;

import  DigestInfo;
import com.github.zhenwei.pkix.operator.MacCalculator;
import java.io.OutputStream;




class MacDataGenerator
{
    private PKCS12MacCalculatorBuilder builder;

    MacDataGenerator(PKCS12MacCalculatorBuilder builder)
    {
        this.builder = builder;
    }

    public MacData build(char[] password, byte[] data)
        throws PKCSException
    {
        MacCalculator macCalculator;

        try
        {
            macCalculator = builder.build(password);

            OutputStream out = macCalculator.getOutputStream();

            out.write(data);

            out.close();
        }
        catch (Exception e)
        {
            throw new PKCSException("unable to process data: " + e.getMessage(), e);
        }

        AlgorithmIdentifier algId = macCalculator.getAlgorithmIdentifier();

        DigestInfo dInfo = new DigestInfo(builder.getDigestAlgorithmIdentifier(), macCalculator.getMac());
        PKCS12PBEParams params = PKCS12PBEParams.getInstance(algId.getParameters());

        return new MacData(dInfo, params.getIV(), params.getIterations().intValue());
    }
}