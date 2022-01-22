package com.github.zhenwei.pkix.dvcs;

import DVCSRequestInformation;
import DVCSTime;
import GeneralNames;
import PolicyInformation;
import com.github.zhenwei.core.util.Arrays;
import java.math.BigInteger;
import java.util.Date;
import org.bouncycastle.tsp.TimeStampToken;


/**
 * Information piece of DVCS requests.
 * It is common for all types of DVCS requests.
 */
public class DVCSRequestInfo
{
    private DVCSRequestInformation data;

    /**
     * Constructs DVCRequestInfo from byte array (DER encoded DVCSRequestInformation).
     *
     * @param in a byte array holding the encoding of a DVCSRequestInformation structure.
     */
    public DVCSRequestInfo(byte[] in)
    {
        this(DVCSRequestInformation.getInstance(in));
    }

    /**
     * Constructs DVCRequestInfo from DVCSRequestInformation ASN.1 structure.
     *
     * @param data a DVCSRequestInformation to populate this object with.
     */
    public DVCSRequestInfo(DVCSRequestInformation data)
    {
        this.data = data;
    }

    /**
     * Converts to corresponding ASN.1 structure (DVCSRequestInformation).
     *
     * @return a DVCSRequestInformation object.
     */
    public DVCSRequestInformation toASN1Structure()
    {
        return data;
    }

    //
    // DVCRequestInfo selector interface
    //

    /**
     * Get DVCS version of request.
     *
     * @return the version number of the request.
     */
    public int getVersion()
    {
        return data.getVersion();
    }

    /**
     * Get requested service type.
     *
     * @return one of CPD, VSD, VPKC, CCPD (see constants).
     */
    public int getServiceType()
    {
        return data.getService().getValue().intValue();
    }

    /**
     * Get nonce if it is set.
     * Note: this field can be set (if not present) or extended (if present) by 
     *
     * @return nonce value, or null if it is not set.
     */
    public BigInteger getNonce()
    {
        return data.getNonce();
    }

    /**
     * Get request generation time if it is set.
     *
     * @return time of request, or null if it is not set.
     * @throws DVCSParsingException if a request time is present but cannot be extracted.
     */
    public Date getRequestTime()
        throws DVCSParsingException
    {
        DVCSTime time = data.getRequestTime();

        if (time == null)
        {
            return null;
        }

        try
        {
            if (time.getGenTime() != null)
            {
                return time.getGenTime().getDate();
            }
            else
            {
                TimeStampToken token = new TimeStampToken(time.getTimeStampToken());

                return token.getTimeStampInfo().getGenTime();
            }
        }
        catch (Exception e)
        {
            throw new DVCSParsingException("unable to extract time: " + e.getMessage(), e);
        }
    }

    /**
     * Get names of requesting entity, if set.
     *
     * @return the requesting entity, or null.
     */
    public GeneralNames getRequester()
    {
        return data.getRequester();
    }

    /**
     * Get policy, under which the validation is requested.
     *
     * @return policy identifier or null, if any policy is acceptable.
     */
    public PolicyInformation getRequestPolicy()
    {
        if (data.getRequestPolicy() != null)
        {
            return data.getRequestPolicy();
        }
        return null;
    }

    /**
     * Get names of DVCS servers.
     * Note: this field can be set by 
     *
     * @return the DVCS names object, or null if not set.
     */
    public GeneralNames getDVCSNames()
    {
        return data.getDVCS();
    }

    /**
     * Get data locations, where the copy of request Data can be obtained.
     * Note: the exact meaning of field is up to applications.
     * Note: this field can be set by 
     *
     * @return the DVCS dataLocations object, or null if not set.
     */
    public GeneralNames getDataLocations()
    {
        return data.getDataLocations();
    }

    /**
     * Compares two DVCRequestInfo structures: one from DVCRequest, and one from DVCResponse.
     * This function implements RFC 3029, 9.1 checks of reqInfo.
     *
     * @param requestInfo  - DVCRequestInfo of DVCRequest
     * @param responseInfo - DVCRequestInfo of DVCResponse
     * @return true if server's requestInfo matches client's requestInfo
     */
    public static boolean validate(
        org.bouncycastle.dvcs.DVCSRequestInfo requestInfo, org.bouncycastle.dvcs.DVCSRequestInfo responseInfo)
    {
        // RFC 3029, 9.1
        // The DVCS MAY modify the fields:
        // 'dvcs', 'requester', 'dataLocations', and 'nonce' of the ReqInfo structure.

        DVCSRequestInformation clientInfo = requestInfo.data;
        DVCSRequestInformation serverInfo = responseInfo.data;

        if (clientInfo.getVersion() != serverInfo.getVersion())
        {
            return false;
        }
        if (!clientEqualsServer(clientInfo.getService(), serverInfo.getService()))
        {
            return false;
        }
        if (!clientEqualsServer(clientInfo.getRequestTime(), serverInfo.getRequestTime()))
        {
            return false;
        }
        if (!clientEqualsServer(clientInfo.getRequestPolicy(), serverInfo.getRequestPolicy()))
        {
            return false;
        }
        if (!clientEqualsServer(clientInfo.getExtensions(), serverInfo.getExtensions()))
        {
            return false;
        }

        // RFC 3029, 9.1. The only modification allowed to a 'nonce'
        // is the inclusion of a new field if it was not present,
        // or to concatenate other data to the end (right) of an existing value.

        if (clientInfo.getNonce() != null)
        {
            if (serverInfo.getNonce() == null)
            {
                return false;
            }
            byte[] clientNonce = clientInfo.getNonce().toByteArray();
            byte[] serverNonce = serverInfo.getNonce().toByteArray();
            if (serverNonce.length < clientNonce.length)
            {
                return false;
            }
            if (!Arrays.areEqual(clientNonce, Arrays.copyOfRange(serverNonce, 0, clientNonce.length)))
            {
                return false;
            }
        }

        return true;
    }

    // null-protected compare of any two objects
    private static boolean clientEqualsServer(Object client, Object server)
    {
        return (client == null && server == null) || (client != null && client.equals(server));
    }
}