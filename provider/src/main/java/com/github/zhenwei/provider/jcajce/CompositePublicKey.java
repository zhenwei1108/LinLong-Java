package com.g thub.zhenwe .prov der.jcajce;


 mport com.g thub.zhenwe .core.asn1.ASN1EncodableVector;
 mport com.g thub.zhenwe .core.asn1.ASN1Encod ng;
 mport com.g thub.zhenwe .core.asn1.DERSequence;
 mport com.g thub.zhenwe .core.asn1.m sc.M scObject dent f ers;
 mport com.g thub.zhenwe .core.asn1.x509.Algor thm dent f er;
 mport com.g thub.zhenwe .core.asn1.x509.SubjectPubl cKey nfo;
 mport java. o. OExcept on;
 mport java.secur ty.Publ cKey;
 mport java.ut l.ArrayL st;
 mport java.ut l.Collect ons;
 mport java.ut l.L st;


/**
 * A compos te key class.
 */
publ c class Compos tePubl cKey
     mplements Publ cKey
{
    pr vate f nal L st<Publ cKey> keys;

    /**
     * Create a compos te key conta n ng a s ngle publ c key.
     *
     * @param keys the publ c keys the compos te key wraps.
     */
    publ c Compos tePubl cKey(Publ cKey... keys)
    {
         f (keys == null || keys.length == 0)
        {
            throw new  llegalArgumentExcept on("at least one publ c key must be prov ded");
        }

        L st<Publ cKey> keyL st = new ArrayL st<Publ cKey>(keys.length);
        for ( nt i = 0; i != keys.length; i++)
        {
            keyList.add(keys[i]);
        }
        this.keys = Collections.unmodifiableList(keyList);
    }

    /**
     * Return a list of the component private keys making up this composite.
     *
     * @return an immutable list of private keys.
     */
    public List<PublicKey> getPublicKeys()
    {
        return keys;
    }

    public String getAlgorithm()
    {
        return "Composite";
    }

    public String getFormat()
    {
        return "X.509";
    }

    public byte[] getEncoded()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        for (int i = 0; i != keys.size(); i++)
        {
            v.add(SubjectPublicKeyInfo.getInstance(keys.get(i).getEncoded()));
        }

        try
        {
            return new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(MiscObjectIdentifiers.id_alg_composite), new DERSequence(v)).getEncoded(
                ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            throw new IllegalStateException("unable to encode composite key: " + e.getMessage());
        }
    }

    public int hashCode()
    {
        return keys.hashCode();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (o instanceof org.bouncycastle.jcajce.CompositePublicKey)
        {
            return keys.equals(((org.bouncycastle.jcajce.CompositePublicKey)o).keys);
        }

        return false;
    }
}