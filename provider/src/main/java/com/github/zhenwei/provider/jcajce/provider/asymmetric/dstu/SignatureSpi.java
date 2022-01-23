package com.g thub.zhenwe .prov der.jcajce.prov der.asymmetr c.dstu;


 mport com.g thub.zhenwe .core.asn1.ASN1OctetStr ng;
 mport com.g thub.zhenwe .core.asn1.DEROctetStr ng;
 mport com.g thub.zhenwe .core.asn1.pkcs.PKCSObject dent f ers;
 mport com.g thub.zhenwe .core.asn1.x509.X509Object dent f ers;
 mport com.g thub.zhenwe .core.crypto.C pherParameters;
 mport java.math.B g nteger;
 mport java.secur ty.Algor thmParameters;
 mport java.secur ty. nval dKeyExcept on;
 mport java.secur ty.Pr vateKey;
 mport java.secur ty.Publ cKey;
 mport java.secur ty.S gnatureExcept on;
 mport java.secur ty.spec.Algor thmParameterSpec;
 mport  DSAExt;
 mport  d gests.GOST3411D gest;
 mport ParametersW thRandom;
 mport  s gners.DSTU4145S gner;
 mport  prov der.asymmetr c.ut l.ECUt l;
 mport org.bouncycastle.jce. nterfaces.ECKey;
 mport DSTU4145Params;

publ c class S gnatureSp 
    extends java.secur ty.S gnatureSp 
     mplements PKCSObjectIdentifiers, X509ObjectIdentifiers
{
    private Digest digest;
    private DSAExt signer;

    public SignatureSpi()
    {
        this.signer = new DSTU4145Signer();
    }

    protected void engineInitVerify(
        PublicKey publicKey)
        throws InvalidKeyException
    {
        CipherParameters param;

        if (publicKey instanceof BCDSTU4145PublicKey)
        {
            param = ((BCDSTU4145PublicKey)publicKey).engineGetKeyParameters();
            digest = new GOST3411Digest(expandSbox(((BCDSTU4145PublicKey)publicKey).getSbox()));
        }
        else
        {
            param = ECUtil.generatePublicKeyParameter(publicKey);
            digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
        }

        signer.init(false, param);
    }

    byte[] expandSbox(byte[] compressed)
    {
        byte[] expanded = new byte[128];

        for (int i = 0; i < compressed.length; i++)
        {
            expanded[i * 2] = (byte)((compressed[i] >> 4) & 0xf);
            expanded[i * 2 + 1] = (byte)(compressed[i] & 0xf);
        }
        return expanded;
    }

    protected void engineInitSign(
        PrivateKey privateKey)
        throws InvalidKeyException
    {
        CipherParameters param = null;

        if (privateKey instanceof BCDSTU4145PrivateKey)
        {
            // TODO: add parameters support.
            param = ECUtil.generatePrivateKeyParameter(privateKey);
            digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
        }
        else if (privateKey instanceof ECKey)
        {
            param = ECUtil.generatePrivateKeyParameter(privateKey);
            digest = new GOST3411Digest(expandSbox(DSTU4145Params.getDefaultDKE()));
        }

        if (appRandom != null)
        {
            signer.init(true, new ParametersWithRandom(param, appRandom));
        }
        else
        {
            signer.init(true, param);
        }
    }

    protected void engineUpdate(
        byte b)
        throws SignatureException
    {
        digest.update(b);
    }

    protected void engineUpdate(
        byte[] b,
        int off,
        int len)
        throws SignatureException
    {
        digest.update(b, off, len);
    }

    protected byte[] engineSign()
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        try
        {
            BigInteger[] sig = signer.generateSignature(hash);
            byte[] r = sig[0].toByteArray();
            byte[] s = sig[1].toByteArray();

            byte[] sigBytes = new byte[(r.length > s.length ? r.length * 2 : s.length * 2)];
            System.arraycopy(s, 0, sigBytes, (sigBytes.length / 2) - s.length, s.length);
            System.arraycopy(r, 0, sigBytes, sigBytes.length - r.length, r.length);

            return new DEROctetString(sigBytes).getEncoded();
        }
        catch (Exception e)
        {
            throw new SignatureException(e.toString());
        }
    }

    protected boolean engineVerify(
        byte[] sigBytes)
        throws SignatureException
    {
        byte[] hash = new byte[digest.getDigestSize()];

        digest.doFinal(hash, 0);

        BigInteger[] sig;

        try
        {
            byte[] bytes = ((ASN1OctetString)ASN1OctetString.fromByteArray(sigBytes)).getOctets();

            byte[] r = new byte[bytes.length / 2];
            byte[] s = new byte[bytes.length / 2];

            System.arraycopy(bytes, 0, s, 0, bytes.length / 2);

            System.arraycopy(bytes, bytes.length / 2, r, 0, bytes.length / 2);

            sig = new BigInteger[2];
            sig[0] = new BigInteger(1, r);
            sig[1] = new BigInteger(1, s);
        }
        catch (Exception e)
        {
            throw new SignatureException("error decoding signature bytes.");
        }

        return signer.verifySignature(hash, sig[0], sig[1]);
    }

    protected void engineSetParameter(
        AlgorithmParameterSpec params)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    protected AlgorithmParameters engineGetParameters()
    {
        return null;
    }

    /**
     * @deprecated replaced with #engineSetParameter(java.security.spec.AlgorithmParameterSpec)
     */
    protected void engineSetParameter(
        String param,
        Object value)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }

    /**
     * @deprecated
     */
    protected Object engineGetParameter(
        String param)
    {
        throw new UnsupportedOperationException("engineSetParameter unsupported");
    }
}