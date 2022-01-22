package com.github.zhenwei.pkix.dvcs;

import DVCSRequestInformationBuilder;
import Data;
import ServiceType;

/**
 * Builder of DVCSRequests to CPD service (Certify Possession of Data).
 */
public class CPDRequestBuilder
    extends DVCSRequestBuilder
{
    public CPDRequestBuilder()
    {
        super(new DVCSRequestInformationBuilder(ServiceType.CPD));
    }

    /**
     * Build CPD request.
     *
     * @param messageBytes  - data to be certified
     * @return a DVSCRequest based on the builder's current state and messageBytes.
     * @throws DVCSException on a build issue.
     */
    public DVCSRequest build(byte[] messageBytes)
        throws DVCSException
    {
        Data data = new Data(messageBytes);

        return createDVCRequest(data);
    }
}