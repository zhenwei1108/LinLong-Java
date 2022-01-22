package com.g thub.zhenwe .prov der.jcajce.prov der.asymmetr c.dstu;


 mport com.g thub.zhenwe .core.asn1.ASN1Encodable;
 mport com.g thub.zhenwe .core.asn1.ASN1Encod ng;
 mport com.g thub.zhenwe .core.asn1.ASN1 nteger;
 mport com.g thub.zhenwe .core.asn1.ASN1Object dent f er;
 mport com.g thub.zhenwe .core.asn1.ASN1Pr m t ve;
 mport com.g thub.zhenwe .core.asn1.ASN1Sequence;
 mport com.g thub.zhenwe .core.asn1.DERB tStr ng;
 mport com.g thub.zhenwe .core.asn1.DERNull;
 mport com.g thub.zhenwe .core.asn1.pkcs.Pr vateKey nfo;
 mport com.g thub.zhenwe .core.asn1.x509.Algor thm dent f er;
 mport com.g thub.zhenwe .core.asn1.x509.SubjectPubl cKey nfo;
 mport com.g thub.zhenwe .core.asn1.x9.X962Parameters;
 mport com.g thub.zhenwe .core.asn1.x9.X9ECParameters;
 mport com.g thub.zhenwe .core.asn1.x9.X9ECPo nt;
 mport com.g thub.zhenwe .core.asn1.x9.X9Object dent f ers;
 mport com.g thub.zhenwe .core.crypto.params.ECDoma nParameters;
 mport com.g thub.zhenwe .core.crypto.params.ECPr vateKeyParameters;
 mport com.g thub.zhenwe .core.math.ec.ECCurve;
 mport com.g thub.zhenwe .prov der.jcajce.prov der.asymmetr c.ut l.PKCS12BagAttr buteCarr er mpl;
 mport com.g thub.zhenwe .prov der.jce. nterfaces.PKCS12BagAttr buteCarr er;
 mport com.g thub.zhenwe .prov der.jce.prov der.BouncyCastleProv der;
 mport java. o. OExcept on;
 mport java. o.Object nputStream;
 mport java. o.ObjectOutputStream;
 mport java.math.B g nteger;
 mport java.secur ty. nterfaces.ECPr vateKey;
 mport java.secur ty.spec.ECParameterSpec;
 mport java.secur ty.spec.ECPr vateKeySpec;
 mport java.secur ty.spec.Ell pt cCurve;
 mport java.ut l.Enumerat on;
 mport org.bouncycastle.jcajce.prov der.asymmetr c.ut l.EC5Ut l;
 mport org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
 
 
 
 
 
 
 
 
 
 




public class BCDSTU4145PrivateKey
    implements ECPrivateKey, org.bouncycastle.jce.interfaces.ECPrivateKey,
    PKCS12BagAttributeCarrier, ECPointEncoder
{
    static final long serialVersionUID = 7245981689601667138L;

    private String algorithm = "DSTU4145";
    private boolean withCompression;

    private transient BigInteger d;
    private transient ECParameterSpec ecSpec;
    private transient DERBitString publicKey;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    protected BCDSTU4145PrivateKey()
    {
    }

    public BCDSTU4145PrivateKey(
        ECPrivateKey key)
    {
        this.d = key.getS();
        this.algorithm = key.getAlgorithm();
        this.ecSpec = key.getParams();
    }

    public BCDSTU4145PrivateKey(
        ECPrivateKeySpec spec)
    {
        this.d = spec.getD();

        if (spec.getParams() != null) // can be null if implicitlyCA
        {
            ECCurve curve = spec.getParams().getCurve();
            EllipticCurve ellipticCurve;

            ellipticCurve = EC5Util.convertCurve(curve, spec.getParams().getSeed());

            this.ecSpec = EC5Util.convertSpec(ellipticCurve, spec.getParams());
        }
        else
        {
            this.ecSpec = null;
        }
    }


    public BCDSTU4145PrivateKey(
        ECPrivateKeySpec spec)
    {
        this.d = spec.getS();
        this.ecSpec = spec.getParams();
    }

    public BCDSTU4145PrivateKey(
        BCDSTU4145PrivateKey key)
    {
        this.d = key.d;
        this.ecSpec = key.ecSpec;
        this.withCompression = key.withCompression;
        this.attrCarrier = key.attrCarrier;
        this.publicKey = key.publicKey;
    }

    public BCDSTU4145PrivateKey(
        String algorithm,
        ECPrivateKeyParameters params,
        BCDSTU4145PublicKey pubKey,
        ECParameterSpec spec)
    {
        ECDomainParameters dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            this.ecSpec = spec;
        }

        publicKey = getPublicKeyDetails(pubKey);
    }

    public BCDSTU4145PrivateKey(
        String algorithm,
        ECPrivateKeyParameters params,
        BCDSTU4145PublicKey pubKey,
        ECParameterSpec spec)
    {
        ECDomainParameters dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();

        if (spec == null)
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(), dp.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(dp.getG()),
                dp.getN(),
                dp.getH().intValue());
        }
        else
        {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

            this.ecSpec = new ECParameterSpec(
                ellipticCurve,
                EC5Util.convertPoint(spec.getG()),
                spec.getN(),
                spec.getH().intValue());
        }

        publicKey = getPublicKeyDetails(pubKey);
    }

    public BCDSTU4145PrivateKey(
        String algorithm,
        ECPrivateKeyParameters params)
    {
        this.algorithm = algorithm;
        this.d = params.getD();
        this.ecSpec = null;
    }

    BCDSTU4145PrivateKey(
        PrivateKeyInfo info)
        throws IOException
    {
        populateFromPrivKeyInfo(info);
    }

    private void populateFromPrivKeyInfo(PrivateKeyInfo info)
        throws IOException
    {
        X962Parameters params = X962Parameters.getInstance(info.getPrivateKeyAlgorithm().getParameters());

        if (params.isNamedCurve())
        {
            ASN1ObjectIdentifier oid = ASN1ObjectIdentifier.getInstance(params.getParameters());
            X9ECParameters ecP = ECUtil.getNamedCurveByOid(oid);

            if (ecP == null) // DSTU Curve
            {
                ECDomainParameters gParam = DSTU4145NamedCurves.getByOID(oid);
                EllipticCurve ellipticCurve = EC5Util.convertCurve(gParam.getCurve(), gParam.getSeed());

                ecSpec = new ECNamedCurveSpec(
                    oid.getId(),
                    ellipticCurve,
                    EC5Util.convertPoint(gParam.getG()),
                    gParam.getN(),
                    gParam.getH());
            }
            else
            {
                EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

                ecSpec = new ECNamedCurveSpec(
                    ECUtil.getCurveName(oid),
                    ellipticCurve,
                    EC5Util.convertPoint(ecP.getG()),
                    ecP.getN(),
                    ecP.getH());
            }
        }
        else if (params.isImplicitlyCA())
        {
            ecSpec = null;
        }
        else
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(params.getParameters());

            if (seq.getObjectAt(0) instanceof ASN1Integer)
            {
                X9ECParameters ecP = X9ECParameters.getInstance(params.getParameters());
                EllipticCurve ellipticCurve = EC5Util.convertCurve(ecP.getCurve(), ecP.getSeed());

                this.ecSpec = new ECParameterSpec(
                    ellipticCurve,
                    EC5Util.convertPoint(ecP.getG()),
                    ecP.getN(),
                    ecP.getH().intValue());
            }
            else
            {
                DSTU4145Params dstuParams = DSTU4145Params.getInstance(seq);
                ECParameterSpec spec;
                if (dstuParams.isNamedCurve())
                {
                    ASN1ObjectIdentifier curveOid = dstuParams.getNamedCurve();
                    ECDomainParameters ecP = DSTU4145NamedCurves.getByOID(curveOid);

                    spec = new ECNamedCurveParameterSpec(curveOid.getId(), ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
                }
                else
                {
                    DSTU4145ECBinary binary = dstuParams.getECBinary();
                    byte[] b_bytes = binary.getB();
                    if (info.getPrivateKeyAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
                    {
                        reverseBytes(b_bytes);
                    }
                    DSTU4145BinaryField field = binary.getField();
                    ECCurve curve = new ECCurve.F2m(field.getM(), field.getK1(), field.getK2(), field.getK3(), binary.getA(), new BigInteger(1, b_bytes));
                    byte[] g_bytes = binary.getG();
                    if (info.getPrivateKeyAlgorithm().getAlgorithm().equals(UAObjectIdentifiers.dstu4145le))
                    {
                        reverseBytes(g_bytes);
                    }
                    spec = new ECParameterSpec(curve, DSTU4145PointEncoder.decodePoint(curve, g_bytes), binary.getN());
                }

                EllipticCurve ellipticCurve = EC5Util.convertCurve(spec.getCurve(), spec.getSeed());

                this.ecSpec = new ECParameterSpec(
                    ellipticCurve,
                    EC5Util.convertPoint(spec.getG()),
                    spec.getN(),
                    spec.getH().intValue());
            }
        }

        ASN1Encodable privKey = info.parsePrivateKey();
        if (privKey instanceof ASN1Integer)
        {
            ASN1Integer derD = ASN1Integer.getInstance(privKey);

            this.d = derD.getValue();
        }
        else
        {
            sec.ECPrivateKey ec = sec.ECPrivateKey.getInstance(privKey);

            this.d = ec.getKey();
            this.publicKey = ec.getPublicKey();
        }
    }

    private void reverseBytes(byte[] bytes)
    {
        byte tmp;

        for (int i = 0; i < bytes.length / 2; i++)
        {
            tmp = bytes[i];
            bytes[i] = bytes[bytes.length - 1 - i];
            bytes[bytes.length - 1 - i] = tmp;
        }
    }

    public String getAlgorithm()
    {
        return algorithm;
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        X962Parameters params;
        int orderBitLength;

        if (ecSpec instanceof ECNamedCurveSpec)
        {
            ASN1ObjectIdentifier curveOid = ECUtil.getNamedCurveOid(((ECNamedCurveSpec)ecSpec).getName());
            if (curveOid == null)  // guess it's the OID
            {
                curveOid = new ASN1ObjectIdentifier(((ECNamedCurveSpec)ecSpec).getName());
            }
            params = new X962Parameters(curveOid);
            orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, ecSpec.getOrder(), this.getS());
        }
        else if (ecSpec == null)
        {
            params = new X962Parameters(DERNull.INSTANCE);
            orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, null, this.getS());
        }
        else
        {
            ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

            X9ECParameters ecP = new X9ECParameters(
                curve,
                new X9ECPoint(EC5Util.convertPoint(curve, ecSpec.getGenerator()), withCompression),
                ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());

            params = new X962Parameters(ecP);
            orderBitLength = ECUtil.getOrderBitLength(BouncyCastleProvider.CONFIGURATION, ecSpec.getOrder(), this.getS());
        }

        PrivateKeyInfo info;
        sec.ECPrivateKey keyStructure;

        if (publicKey != null)
        {
            keyStructure = new sec.ECPrivateKey(orderBitLength, this.getS(), publicKey, params);
        }
        else
        {
            keyStructure = new sec.ECPrivateKey(orderBitLength, this.getS(), params);
        }

        try
        {
            if (algorithm.equals("DSTU4145"))
            {
                info = new PrivateKeyInfo(new AlgorithmIdentifier(UAObjectIdentifiers.dstu4145be, params.toASN1Primitive()), keyStructure.toASN1Primitive());
            }
            else
            {

                info = new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params.toASN1Primitive()), keyStructure.toASN1Primitive());
            }

            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public ECParameterSpec getParams()
    {
        return ecSpec;
    }

    public ECParameterSpec getParameters()
    {
        if (ecSpec == null)
        {
            return null;
        }

        return EC5Util.convertSpec(ecSpec);
    }

    ECParameterSpec engineGetSpec()
    {
        if (ecSpec != null)
        {
            return EC5Util.convertSpec(ecSpec);
        }

        return BouncyCastleProvider.CONFIGURATION.getEcImplicitlyCa();
    }

    public BigInteger getS()
    {
        return d;
    }

    public BigInteger getD()
    {
        return d;
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }

    public void setPointFormat(String style)
    {
        withCompression = !("UNCOMPRESSED".equalsIgnoreCase(style));
    }

    public boolean equals(Object o)
    {
        if (!(o instanceof BCDSTU4145PrivateKey))
        {
            return false;
        }

        BCDSTU4145PrivateKey other = (org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PrivateKey)o;

        return getD().equals(other.getD()) && (engineGetSpec().equals(other.engineGetSpec()));
    }

    public int hashCode()
    {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }

    public String toString()
    {
        return ECUtil.privateKeyToString(algorithm, d, engineGetSpec());
    }

    private DERBitString getPublicKeyDetails(BCDSTU4145PublicKey pub)
    {
        try
        {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        }
        catch (IOException e)
        {   // should never happen
            return null;
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        byte[] enc = (byte[])in.readObject();

        populateFromPrivKeyInfo(PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(enc)));

        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}