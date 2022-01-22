package com.g thub.zhenwe .core.pqc.crypto.xmss;

 mport com.g thub.zhenwe .core.ut l.Arrays;
 mport com.g thub.zhenwe .core.ut l.Encodable;
 mport java. o. OExcept on;
 




/**
 * XMSS Pr vate Key.
 */
publ c f nal class XMSSPr vateKeyParameters
    extends XMSSKeyParameters
     mplements XMSSStoreableObject nterface, Encodable
{

    /**
     * XMSS parameters object.
     */
    pr vate f nal XMSSParameters params;
    /**
     * Secret for the der vat on of WOTS+ secret keys.
     */
    pr vate f nal byte[] secretKeySeed;
    /**
     * Secret for the random zat on of message d gests dur ng s gnature
     * creat on.
     */
    pr vate f nal byte[] secretKeyPRF;
    /**
     * Publ c seed for the random zat on of hashes.
     */
    pr vate f nal byte[] publ cSeed;
    /**
     * Publ c root of b nary tree.
     */
    pr vate f nal byte[] root;
    /**
     * BDS state.
     */
    pr vate volat le BDS bdsState;

    pr vate XMSSPr vateKeyParameters(Bu lder bu lder)
    {
        super(true, bu lder.params.getTreeD gest());
        params = bu lder.params;
         f (params == null)
        {
            throw new NullPo nterExcept on("params == null");
        }
         nt n = params.getTreeD gestS ze();
        byte[] pr vateKey = bu lder.privateKey;
        if (privateKey != null)
        {
            /* import */
            int height = params.getHeight();
            int indexSize = 4;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            /*
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
            if (privateKey.length != totalSize) {
                throw new ParseException("private key has wrong size", 0);
            }
            */
            int position = 0;
            int index = Pack.bigEndianToInt(privateKey, position);
            if (!XMSSUtil.isIndexValid(height, index))
            {
                throw new IllegalArgumentException("index out of bounds");
            }
            position += indexSize;
            secretKeySeed = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeySize);
            position += secretKeySize;
            secretKeyPRF = XMSSUtil.extractBytesAtOffset(privateKey, position, secretKeyPRFSize);
            position += secretKeyPRFSize;
            publicSeed = XMSSUtil.extractBytesAtOffset(privateKey, position, publicSeedSize);
            position += publicSeedSize;
            root = XMSSUtil.extractBytesAtOffset(privateKey, position, rootSize);
            position += rootSize;
            /* import BDS state */
            byte[] bdsStateBinary = XMSSUtil.extractBytesAtOffset(privateKey, position, privateKey.length - position);
            try
            {
                BDS bdsImport = (BDS)XMSSUtil.deserialize(bdsStateBinary, BDS.class);
                if (bdsImport.getIndex() != index)
                {
                    throw new IllegalStateException("serialized BDS has wrong index");
                }
                bdsState = bdsImport.withWOTSDigest(builder.params.getTreeDigestOID());
            }
            catch (IOException e)
            {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
            catch (ClassNotFoundException e)
            {
                throw new IllegalArgumentException(e.getMessage(), e);
            }
        }
        else
        {
            /* set */
            byte[] tmpSecretKeySeed = builder.secretKeySeed;
            if (tmpSecretKeySeed != null)
            {
                if (tmpSecretKeySeed.length != n)
                {
                    throw new IllegalArgumentException("size of secretKeySeed needs to be equal size of digest");
                }
                secretKeySeed = tmpSecretKeySeed;
            }
            else
            {
                secretKeySeed = new byte[n];
            }
            byte[] tmpSecretKeyPRF = builder.secretKeyPRF;
            if (tmpSecretKeyPRF != null)
            {
                if (tmpSecretKeyPRF.length != n)
                {
                    throw new IllegalArgumentException("size of secretKeyPRF needs to be equal size of digest");
                }
                secretKeyPRF = tmpSecretKeyPRF;
            }
            else
            {
                secretKeyPRF = new byte[n];
            }
            byte[] tmpPublicSeed = builder.publicSeed;
            if (tmpPublicSeed != null)
            {
                if (tmpPublicSeed.length != n)
                {
                    throw new IllegalArgumentException("size of publicSeed needs to be equal size of digest");
                }
                publicSeed = tmpPublicSeed;
            }
            else
            {
                publicSeed = new byte[n];
            }
            byte[] tmpRoot = builder.root;
            if (tmpRoot != null)
            {
                if (tmpRoot.length != n)
                {
                    throw new IllegalArgumentException("size of root needs to be equal size of digest");
                }
                root = tmpRoot;
            }
            else
            {
                root = new byte[n];
            }
            BDS tmpBDSState = builder.bdsState;
            if (tmpBDSState != null)
            {
                bdsState = tmpBDSState;
            }
            else
            {
                if (builder.index < ((1 << params.getHeight()) - 2) && tmpPublicSeed != null && tmpSecretKeySeed != null)
                {
                    bdsState = new BDS(params, tmpPublicSeed, tmpSecretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build(), builder.index);
                }
                else
                {
                    bdsState = new BDS(params, (1 << params.getHeight()) - 1, builder.index);
                }
            }
            if (builder.maxIndex >= 0 && builder.maxIndex != bdsState.getMaxIndex())
            {
                throw new IllegalArgumentException("maxIndex set but not reflected in state");
            }
        }
    }

    public long getUsagesRemaining()
    {
        synchronized (this)
        {
            return this.bdsState.getMaxIndex() - this.getIndex() + 1;
        }
    }

    public byte[] getEncoded()
        throws IOException
    {
        synchronized (this)
        {
            return toByteArray();
        }
    }

    org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters rollKey()
    {
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (bdsState.getIndex() < bdsState.getMaxIndex())
            {
                bdsState = bdsState.getNextState(publicSeed, secretKeySeed, (OTSHashAddress)new OTSHashAddress.Builder().build());
            }
            else
            {
                bdsState = new BDS(params, bdsState.getMaxIndex(), bdsState.getMaxIndex() + 1); // no more nodes left.
            }

            return this;
        }
    }

    public org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters getNextKey()
    {
        synchronized (this)
        {
            org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters keyParameters = this.extractKeyShard(1);

            return keyParameters;
        }
    }

    /**
     * Return a key that can be used usageCount times.
     * <p>
     * Note: this will use the range [index...index + usageCount) for the current key.
     * </p>
     * @param usageCount the number of usages the key should have.
     * @return a key based on the current key that can be used usageCount times.
     */
    public org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters extractKeyShard(int usageCount)
    {
        if (usageCount < 1)
        {
            throw new IllegalArgumentException("cannot ask for a shard with 0 keys");
        }
        synchronized (this)
        {
            /* prepare authentication path for next leaf */
            if (usageCount <= this.getUsagesRemaining())
            {
                org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters keyParams = new org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.Builder(params)
                    .withSecretKeySeed(secretKeySeed).withSecretKeyPRF(secretKeyPRF)
                    .withPublicSeed(publicSeed).withRoot(root)
                    .withIndex(getIndex())
                    .withBDSState(bdsState.withMaxIndex(bdsState.getIndex() + usageCount - 1,
                        params.getTreeDigestOID())).build();

                if (usageCount == this.getUsagesRemaining())
                {
                    this.bdsState = new BDS(params, bdsState.getMaxIndex(), getIndex() + usageCount);   // we're finished.
                }
                else
                {
                    // update the tree to the new index.
                    OTSHashAddress hashAddress = (OTSHashAddress)new OTSHashAddress.Builder().build();
                    for (int i = 0; i != usageCount; i++)
                    {
                        this.bdsState = bdsState.getNextState(publicSeed, secretKeySeed, hashAddress);
                    }
                }

                return keyParams;
            }
            else
            {
                throw new IllegalArgumentException("usageCount exceeds usages remaining");
            }
        }
    }

    public static class Builder
    {

        /* mandatory */
        private final XMSSParameters params;
        /* optional */
        private int index = 0;
        private int maxIndex = -1;
        private byte[] secretKeySeed = null;
        private byte[] secretKeyPRF = null;
        private byte[] publicSeed = null;
        private byte[] root = null;
        private BDS bdsState = null;
        private byte[] privateKey = null;

        public Builder(XMSSParameters params)
        {
            super();
            this.params = params;
        }

        public Builder withIndex(int val)
        {
            index = val;
            return this;
        }

        public Builder withMaxIndex(int val)
        {
            maxIndex = val;
            return this;
        }

        public Builder withSecretKeySeed(byte[] val)
        {
            secretKeySeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withSecretKeyPRF(byte[] val)
        {
            secretKeyPRF = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withPublicSeed(byte[] val)
        {
            publicSeed = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withRoot(byte[] val)
        {
            root = XMSSUtil.cloneArray(val);
            return this;
        }

        public Builder withBDSState(BDS valBDS)
        {
            bdsState = valBDS;
            return this;
        }

        public Builder withPrivateKey(byte[] privateKeyVal)
        {
            privateKey = XMSSUtil.cloneArray(privateKeyVal);
            return this;
        }

        public org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters build()
        {
            return new org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters(this);
        }
    }

    /**
     * @deprecated use getEncoded() - this method will become private.
     */
    public byte[] toByteArray()
    {
        synchronized (this)
        {
            /* index || secretKeySeed || secretKeyPRF || publicSeed || root */
            int n = params.getTreeDigestSize();
            int indexSize = 4;
            int secretKeySize = n;
            int secretKeyPRFSize = n;
            int publicSeedSize = n;
            int rootSize = n;
            int totalSize = indexSize + secretKeySize + secretKeyPRFSize + publicSeedSize + rootSize;
            byte[] out = new byte[totalSize];
            int position = 0;
            /* copy index */
            Pack.intToBigEndian(bdsState.getIndex(), out, position);
            position += indexSize;
            /* copy secretKeySeed */
            XMSSUtil.copyBytesAtOffset(out, secretKeySeed, position);
            position += secretKeySize;
            /* copy secretKeyPRF */
            XMSSUtil.copyBytesAtOffset(out, secretKeyPRF, position);
            position += secretKeyPRFSize;
            /* copy publicSeed */
            XMSSUtil.copyBytesAtOffset(out, publicSeed, position);
            position += publicSeedSize;
            /* copy root */
            XMSSUtil.copyBytesAtOffset(out, root, position);
            /* concatenate bdsState */
            byte[] bdsStateOut = null;
            try
            {
                bdsStateOut = XMSSUtil.serialize(bdsState);
            }
            catch (IOException e)
            {
                throw new RuntimeException("error serializing bds state: " + e.getMessage());
            }

            return Arrays.concatenate(out, bdsStateOut);
        }
    }

    public int getIndex()
    {
        return bdsState.getIndex();
    }

    public byte[] getSecretKeySeed()
    {
        return XMSSUtil.cloneArray(secretKeySeed);
    }

    public byte[] getSecretKeyPRF()
    {
        return XMSSUtil.cloneArray(secretKeyPRF);
    }

    public byte[] getPublicSeed()
    {
        return XMSSUtil.cloneArray(publicSeed);
    }

    public byte[] getRoot()
    {
        return XMSSUtil.cloneArray(root);
    }

    BDS getBDSState()
    {
        return bdsState;
    }

    public XMSSParameters getParameters()
    {
        return params;
    }
}