package com.github.zhenwei.pkix.its.bc;

import com.github.zhenwei.pkix.its.ITSCertificate;
import com.github.zhenwei.pkix.its.ITSImplicitCertificateBuilder;
import com.github.zhenwei.pkix.util.oer.its.ToBeSignedCertificate;
import  com.github.zhenwei.pkix.operator.bc.BcDigestCalculatorProvider;

public class BcITSImplicitCertificateBuilder
    extends ITSImplicitCertificateBuilder
{
    public BcITSImplicitCertificateBuilder(ITSCertificate issuer, ToBeSignedCertificate.Builder tbsCertificate)
    {
        super(issuer, new BcDigestCalculatorProvider(), tbsCertificate);
    }
}