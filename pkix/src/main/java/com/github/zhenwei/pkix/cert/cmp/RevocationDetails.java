package com.github.zhenwei.pkix.cert.cmp;


import cmp.RevDetails;
import java.math.BigInteger;

public class RevocationDetails
{
    private RevDetails revDetails;

    public RevocationDetails(RevDetails revDetails)
    {
        this.revDetails = revDetails;
    }

    public X500Name getSubject()
    {
        return revDetails.getCertDetails().getSubject();
    }

    public X500Name getIssuer()
    {
        return revDetails.getCertDetails().getIssuer();
    }

    public BigInteger getSerialNumber()
    {
        return revDetails.getCertDetails().getSerialNumber().getValue();
    }

    public RevDetails toASN1Structure()
    {
        return revDetails;
    }
}