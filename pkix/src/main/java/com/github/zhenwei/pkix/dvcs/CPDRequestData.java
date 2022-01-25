package com.github.zhenwei.pkix.dvcs;

import com.github.zhenwei.pkix.util.asn1.dvcs.Data;

/**
 * Data piece of DVCRequest for CPD service (Certify Possession of Data).
 * It contains CPD-specific selector interface.
 * <p>
 * This objects are constructed internally,
 * to build DVCS request to CPD service use CPDRequestBuilder.
 * </p>
 */
public class CPDRequestData
    extends DVCSRequestData
{
    CPDRequestData(Data data)
        throws DVCSConstructionException
    {
        super(data);
        initMessage();
    }

    private void initMessage()
        throws DVCSConstructionException
    {
        if (data.getMessage() == null)
        {
            throw new DVCSConstructionException("DVCSRequest.data.message should be specified for CPD service");
        }
    }

    /**
     * Get contained message (data to be certified).
     *
     * @return the contained message.
     */
    public byte[] getMessage()
    {
        return data.getMessage().getOctets();
    }
}