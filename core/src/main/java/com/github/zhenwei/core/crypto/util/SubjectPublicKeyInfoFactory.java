package com.github.zhenwei.core.crypto.util;


import com.github.zhenwei.core.asn1.ASN1Encodable;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.DEROctetString;
import com.github.zhenwei.core.asn1.cryptopro.CryptoProObjectIdentifiers;
import com.github.zhenwei.core.asn1.cryptopro.GOST3410PublicKeyAlgParameters;
import com.github.zhenwei.core.asn1.edec.EdECObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.rosstandart.RosstandartObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.DSAParameter;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x9.X962Parameters;
import com.github.zhenwei.core.asn1.x9.X9ECParameters;
import com.github.zhenwei.core.asn1.x9.X9ECPoint;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import com.github.zhenwei.core.crypto.params.DSAPublicKeyParameters;
import com.github.zhenwei.core.crypto.params.ECDomainParameters;
import com.github.zhenwei.core.crypto.params.ECGOST3410Parameters;
import com.github.zhenwei.core.crypto.params.ECNamedDomainParameters;
import com.github.zhenwei.core.crypto.params.ECPublicKeyParameters;
import com.github.zhenwei.core.crypto.params.Ed25519PublicKeyParameters;
import com.github.zhenwei.core.crypto.params.Ed448PublicKeyParameters;
import com.github.zhenwei.core.crypto.params.RSAKeyParameters;
import com.github.zhenwei.core.crypto.params.X25519PublicKeyParameters;
import com.github.zhenwei.core.crypto.params.X448PublicKeyParameters;
import java.io.IOException;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

;

 




/**
 * Factory to create ASN.1 subject public key info objects from lightweight public keys.
 */
public class SubjectPublicKeyInfoFactory
{
    private static Set cryptoProOids = new HashSet(5);

    static
    {
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_A);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_B);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_C);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchA);
        cryptoProOids.add(CryptoProObjectIdentifiers.gostR3410_2001_CryptoPro_XchB);
    }

    private SubjectPublicKeyInfoFactory()
    {

    }

    /**
     * Create a SubjectPublicKeyInfo public key.
     *
     * @param publicKey the key to be encoded into the info object.
     * @return a SubjectPublicKeyInfo representing the key.
     * @throws IOException on an error encoding the key
     */
    public static SubjectPublicKeyInfo createSubjectPublicKeyInfo(AsymmetricKeyParameter publicKey)
        throws IOException
    {
        if (publicKey instanceof RSAKeyParameters)
        {
            RSAKeyParameters pub = (RSAKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), new RSAPublicKey(pub.getModulus(), pub.getExponent()));
        }
        else if (publicKey instanceof DSAPublicKeyParameters)
        {
            DSAPublicKeyParameters pub = (DSAPublicKeyParameters)publicKey;

            DSAParameter params = null;
            DSAParameters dsaParams = pub.getParameters();
            if (dsaParams != null)
            {
                params = new DSAParameter(dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
            }

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, params), new ASN1Integer(pub.getY()));
        }
        else if (publicKey instanceof ECPublicKeyParameters)
        {
            ECPublicKeyParameters pub = (ECPublicKeyParameters)publicKey;
            ECDomainParameters domainParams = pub.getParameters();
            ASN1Encodable params;

            if (domainParams == null)
            {
                params = new X962Parameters(DERNull.INSTANCE);      // Implicitly CA
            }
            else if (domainParams instanceof ECGOST3410Parameters)
            {
                ECGOST3410Parameters gostParams = (ECGOST3410Parameters)domainParams;

                BigInteger bX = pub.getQ().getAffineXCoord().toBigInteger();
                BigInteger bY = pub.getQ().getAffineYCoord().toBigInteger();

                params = new GOST3410PublicKeyAlgParameters(gostParams.getPublicKeyParamSet(), gostParams.getDigestParamSet());

                int encKeySize;
                int offset;
                ASN1ObjectIdentifier algIdentifier;


                if (cryptoProOids.contains(gostParams.getPublicKeyParamSet()))
                {
                    encKeySize = 64;
                    offset = 32;
                    algIdentifier = CryptoProObjectIdentifiers.gostR3410_2001;
                }
                else
                {
                    boolean is512 = (bX.bitLength() > 256);
                    if (is512)
                    {
                        encKeySize = 128;
                        offset = 64;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_512;
                    }
                    else
                    {
                        encKeySize = 64;
                        offset = 32;
                        algIdentifier = RosstandartObjectIdentifiers.id_tc26_gost_3410_12_256;
                    }
                }

                byte[] encKey = new byte[encKeySize];
                extractBytes(encKey, encKeySize / 2, 0, bX);
                extractBytes(encKey, encKeySize / 2, offset, bY);

                try
                {
                    return new SubjectPublicKeyInfo(new AlgorithmIdentifier(algIdentifier, params), new DEROctetString(encKey));
                }
                catch (IOException e)
                {
                    return null;
                }
            }
            else if (domainParams instanceof ECNamedDomainParameters)
            {
                params = new X962Parameters(((ECNamedDomainParameters)domainParams).getName());
            }
            else
            {
                X9ECParameters ecP = new X9ECParameters(
                    domainParams.getCurve(),
                    // TODO Support point compression
                    new X9ECPoint(domainParams.getG(), false),
                    domainParams.getN(),
                    domainParams.getH(),
                    domainParams.getSeed());

                params = new X962Parameters(ecP);
            }

            // TODO Support point compression
            byte[] pubKeyOctets = pub.getQ().getEncoded(false);

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, params), pubKeyOctets);
        }
        else if (publicKey instanceof X448PublicKeyParameters)
        {
            X448PublicKeyParameters key = (X448PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X448), key.getEncoded());
        }
        else if (publicKey instanceof X25519PublicKeyParameters)
        {
            X25519PublicKeyParameters key = (X25519PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_X25519), key.getEncoded());
        }
        else if (publicKey instanceof Ed448PublicKeyParameters)
        {
            Ed448PublicKeyParameters key = (Ed448PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448), key.getEncoded());
        }
        else if (publicKey instanceof Ed25519PublicKeyParameters)
        {
            Ed25519PublicKeyParameters key = (Ed25519PublicKeyParameters)publicKey;

            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), key.getEncoded());
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }

    private static void extractBytes(byte[] encKey, int size, int offSet, BigInteger bI)
    {
        byte[] val = bI.toByteArray();
        if (val.length < size)
        {
            byte[] tmp = new byte[size];
            System.arraycopy(val, 0, tmp, tmp.length - val.length, val.length);
            val = tmp;
        }

        for (int i = 0; i != size; i++)
        {
            encKey[offSet + i] = val[val.length - 1 - i];
        }
    }
}