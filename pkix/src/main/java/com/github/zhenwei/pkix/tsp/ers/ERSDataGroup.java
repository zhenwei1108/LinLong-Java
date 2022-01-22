package com.github.zhenwei.pkix.tsp.ers;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.operator.DigestCalculator;

/**
 * Representation of data groups with more than 1 members according to the description provided in RFC4998.
 * <p>
 * Such data groups represent a set of one or more data objects (e.g. electronic documents) for
 * which an Evidence Record should be generated. Data groups will be encapsulated in a single
 * PartialHashtree so that the presence of the group can be checked for, as well as the
 * individual items that make it up.
 */
public class ERSDataGroup
    extends ERSCachingData
{
    protected List<ERSData> dataObjects;

    /**
     * Base constructor for an "array" of data objects.
     *
     * @param dataObjects an array of data objects.
     */
    public ERSDataGroup(ERSData... dataObjects)
    {
        this.dataObjects = new ArrayList<ERSData>(dataObjects.length);
        this.dataObjects.addAll(Arrays.asList(dataObjects));
    }

    /**
     * Base constructor using a list of data objects.
     *
     * @param dataObjects a list of data objects.
     */
    public ERSDataGroup(List<ERSData> dataObjects)
    {
        this.dataObjects = new ArrayList<ERSData>(dataObjects.size());
        this.dataObjects.addAll(dataObjects);
    }

    /**
     * Constructor for a group with a single object.
     *
     * @param dataObject the data object to go in the group.
     */
    public ERSDataGroup(ERSData dataObject)
    {
        this.dataObjects = Collections.singletonList(dataObject);
    }

    /**
     * Generates hashes for all the data objects included in the data group.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hashes
     * @return the set of hashes, in ascending order
     */
    public List<byte[]> getHashes(
        final DigestCalculator digestCalculator)
    {
        return ERSUtil.buildHashList(digestCalculator, dataObjects);
    }

    /**
     * Generates a hash for the whole DataGroup.
     *
     * @param digestCalculator the {@link DigestCalculator} to use for computing the hash
     * @return a hash that is representative of the whole DataGroup
     */
    protected byte[] calculateHash(DigestCalculator digestCalculator)
    {
        List<byte[]> hashes = getHashes(digestCalculator);

        if (hashes.size() > 1)
        {
            return ERSUtil.calculateDigest(digestCalculator, hashes.iterator());
        }
        else
        {
            return (byte[])hashes.get(0);
        }
    }

    /**
     * Return the number of data objects present in the group.
     *
     * @return membership count of the group.
     */
    public int size()
    {
        return dataObjects.size();
    }
}