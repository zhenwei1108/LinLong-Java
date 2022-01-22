package com.github.zhenwei.pkix.tsp;



import Extensions;

import java.io.IOException;
import java.math.BigInteger;
import java.text.ParseException;
import java.util.Date;
import tsp.Accuracy;
import tsp.TSTInfo;

public class TimeStampTokenInfo
{
    TSTInfo tstInfo;
    Date    genTime;
    
    TimeStampTokenInfo(TSTInfo tstInfo)
        throws TSPException, IOException
    {
        this.tstInfo = tstInfo;

        try
        {
            this.genTime = tstInfo.getGenTime().getDate();
        }
        catch (ParseException e)
        {
            throw new TSPException("unable to parse genTime field");
        }
    }

    public boolean isOrdered()
    {
        return tstInfo.getOrdering().isTrue();
    }

    public Accuracy getAccuracy()
    {
        return tstInfo.getAccuracy();
    }

    public Date getGenTime()
    {
        return genTime;
    }

    public GenTimeAccuracy getGenTimeAccuracy()
    {
        if (this.getAccuracy() != null)
        {
            return new GenTimeAccuracy(this.getAccuracy());
        }
        
        return null;
    }
    
    public ASN1ObjectIdentifier getPolicy()
    {
        return tstInfo.getPolicy();
    }
    
    public BigInteger getSerialNumber()
    {
        return tstInfo.getSerialNumber().getValue();
    }

    public GeneralName getTsa()
    {
        return tstInfo.getTsa();
    }

    public Extensions getExtensions()
    {
        return tstInfo.getExtensions();
    }

    /**
     * @return the nonce value, null if there isn't one.
     */
    public BigInteger getNonce()
    {
        if (tstInfo.getNonce() != null)
        {
            return tstInfo.getNonce().getValue();
        }

        return null;
    }

    public AlgorithmIdentifier getHashAlgorithm()
    {
        return tstInfo.getMessageImprint().getHashAlgorithm();
    }

    public ASN1ObjectIdentifier getMessageImprintAlgOID()
    {
        return tstInfo.getMessageImprint().getHashAlgorithm().getAlgorithm();
    }

    public byte[] getMessageImprintDigest()
    {
        return tstInfo.getMessageImprint().getHashedMessage();
    }

    public byte[] getEncoded() 
        throws IOException
    {
        return tstInfo.getEncoded();
    }

    /**
     * @deprecated use toASN1Structure
     */
    public TSTInfo toTSTInfo()
    {
        return tstInfo;
    }

    public TSTInfo toASN1Structure()
    {
        return tstInfo;
    }
}