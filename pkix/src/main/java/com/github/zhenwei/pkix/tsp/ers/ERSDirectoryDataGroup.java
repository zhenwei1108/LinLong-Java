package com.github.zhenwei.pkix.tsp.ers;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.tsp.ers.ERSData;
import org.bouncycastle.tsp.ers.ERSDataGroup;
import org.bouncycastle.tsp.ers.ERSFileData;

/**
 * Representation of a data group based on a directory. Sub-directories will be
 * represented by a single hash.
 */
public class ERSDirectoryDataGroup
    extends ERSDataGroup
{
    /**
     * Base constructor for a directory of data objects.
     *
     * @param dataDirectory a directory of data objects.
     */
    public ERSDirectoryDataGroup(File dataDirectory)
        throws FileNotFoundException
    {
        super(buildGroup(dataDirectory));
    }

    private static List<ERSData> buildGroup(File dataDirectory)
        throws FileNotFoundException
    {
        if (dataDirectory.isDirectory())
        {
            File[] files = dataDirectory.listFiles();
            List<ERSData> dataObjects = new ArrayList<ERSData>(files.length);
            for (int i = 0; i != files.length; i++)
            {
                if (files[i].isDirectory())
                {
                    if (files[i].listFiles().length != 0)
                    {
                        dataObjects.add(new org.bouncycastle.tsp.ers.ERSDirectoryDataGroup(files[i]));
                    }
                }
                else
                {
                    dataObjects.add(new ERSFileData(files[i]));
                }
            }

            return dataObjects;
        }
        else
        {
            throw new IllegalArgumentException("file reference does not refer to directory");
        }
    }

    /**
     * Return a list of the plain files in this data group.
     *
     * @return a list of file data.
     */
    public List<ERSFileData> getFiles()
    {
        List<ERSFileData> files = new ArrayList<ERSFileData>();
        for (int i = 0; i != dataObjects.size(); i++)
        {
            if (dataObjects.get(i) instanceof ERSFileData)
            {
                files.add((ERSFileData)dataObjects.get(i));
            }
        }
        return files;
    }

    /**
     * Return a list of the subdirectories in this data group.
     *
     * @return a list of subdirectories.
     */
    public List<org.bouncycastle.tsp.ers.ERSDirectoryDataGroup> getSubdirectories()
    {
        List<org.bouncycastle.tsp.ers.ERSDirectoryDataGroup> subdirectories = new ArrayList<org.bouncycastle.tsp.ers.ERSDirectoryDataGroup>();
        for (int i = 0; i != dataObjects.size(); i++)
        {
            if (dataObjects.get(i) instanceof org.bouncycastle.tsp.ers.ERSDirectoryDataGroup)
            {
                subdirectories.add((org.bouncycastle.tsp.ers.ERSDirectoryDataGroup)dataObjects.get(i));
            }
        }
        return subdirectories;
    }
}