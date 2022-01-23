package com.github.zhenwei.pkix.cert.crmf;


import com.github.zhenwei.core.asn1.ASN1Encoding;
import  SubjectPublicKeyInfo;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.pkix.operator.MacCalculator;
import crmf.PKMACValue;
import java.io.IOException;
import java.io.OutputStream;



class PKMACValueVerifier
{
    private final PKMACBuilder builder;

    public PKMACValueVerifier(PKMACBuilder builder)
    {
        this.builder = builder;
    }

    public boolean isValid(PKMACValue value, char[] password, SubjectPublicKeyInfo keyInfo)
        throws CRMFException
    {
        builder.setParameters(PBMParameter.getInstance(value.getAlgId().getParameters()));
        MacCalculator calculator = builder.build(password);

        OutputStream macOut = calculator.getOutputStream();

        try
        {
            macOut.write(keyInfo.getEncoded(ASN1Encoding.DER));

            macOut.close();
        }
        catch (IOException e)
        {
            throw new CRMFException("exception encoding mac input: " + e.getMessage(), e);
        }

        return Arrays.constantTimeAreEqual(calculator.getMac(), value.getValue().getBytes());
    }
}