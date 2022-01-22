package com.github.zhenwei.pkix.openssl;


import cms.ContentInfo;
import com.github.zhenwei.core.asn1.ASN1InputStream;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.DERNull;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.asn1.x509.DSAParameter;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x9.X9ECParameters;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.core.util.encoders.Hex;
import com.github.zhenwei.core.util.io.pem.PemHeader;
import com.github.zhenwei.core.util.io.pem.PemObject;
import com.github.zhenwei.pkix.cert.X509AttributeCertificateHolder;
import com.github.zhenwei.pkix.cert.X509CRLHolder;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import java.io.IOException;
import java.io.Reader;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import  io.pem.PemObjectParser;
import  io.pem.PemReader;
import EncryptedPrivateKeyInfo;
 



/**
 * Class for parsing OpenSSL PEM encoded streams containing
 * X509 certificates, PKCS8 encoded keys and PKCS7 objects.
 * <p>
 * In the case of PKCS7 objects the reader will return a CMS ContentInfo object. Public keys will be returned as
 * well formed SubjectPublicKeyInfo objects, private keys will be returned as well formed PrivateKeyInfo objects. In the
 * case of a private key a PEMKeyPair will normally be returned if the encoding contains both the private and public
 * key definition. CRLs, Certificates, PKCS#10 requests, and Attribute Certificates will generate the appropriate BC holder class.
 * </p>
 */
public class PEMParser
    extends PemReader
{
    public static final String TYPE_CERTIFICATE_REQUEST = "CERTIFICATE REQUEST";
    public static final String TYPE_NEW_CERTIFICATE_REQUEST = "NEW CERTIFICATE REQUEST";
    public static final String TYPE_CERTIFICATE = "CERTIFICATE";
    public static final String TYPE_TRUSTED_CERTIFICATE = "TRUSTED CERTIFICATE";
    public static final String TYPE_X509_CERTIFICATE = "X509 CERTIFICATE";
    public static final String TYPE_X509_CRL = "X509 CRL";
    public static final String TYPE_PKCS7 = "PKCS7";
    public static final String TYPE_CMS = "CMS";
    public static final String TYPE_ATTRIBUTE_CERTIFICATE = "ATTRIBUTE CERTIFICATE";
    public static final String TYPE_EC_PARAMETERS = "EC PARAMETERS";
    public static final String TYPE_PUBLIC_KEY = "PUBLIC KEY";
    public static final String TYPE_RSA_PUBLIC_KEY = "RSA PUBLIC KEY";
    public static final String TYPE_RSA_PRIVATE_KEY = "RSA PRIVATE KEY";
    public static final String TYPE_DSA_PRIVATE_KEY = "DSA PRIVATE KEY";
    public static final String TYPE_EC_PRIVATE_KEY = "EC PRIVATE KEY";
    public static final String TYPE_ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY";
    public static final String TYPE_PRIVATE_KEY = "PRIVATE KEY";

    protected final Map parsers = new HashMap();

    /**
     * Create a new PEMReader
     *
     * @param reader the Reader
     */
    public PEMParser(
        Reader reader)
    {
        super(reader);

        parsers.put(TYPE_CERTIFICATE_REQUEST, new PKCS10CertificationRequestParser());
        parsers.put(TYPE_NEW_CERTIFICATE_REQUEST, new PKCS10CertificationRequestParser());
        parsers.put(TYPE_CERTIFICATE, new X509CertificateParser());
        parsers.put(TYPE_TRUSTED_CERTIFICATE, new X509TrustedCertificateParser());
        parsers.put(TYPE_X509_CERTIFICATE, new X509CertificateParser());
        parsers.put(TYPE_X509_CRL, new X509CRLParser());
        parsers.put(TYPE_PKCS7, new PKCS7Parser());
        parsers.put(TYPE_CMS, new PKCS7Parser());
        parsers.put(TYPE_ATTRIBUTE_CERTIFICATE, new X509AttributeCertificateParser());
        parsers.put(TYPE_EC_PARAMETERS, new ECCurveParamsParser());
        parsers.put(TYPE_PUBLIC_KEY, new PublicKeyParser());
        parsers.put(TYPE_RSA_PUBLIC_KEY, new RSAPublicKeyParser());
        parsers.put(TYPE_RSA_PRIVATE_KEY, new KeyPairParser(new RSAKeyPairParser()));
        parsers.put(TYPE_DSA_PRIVATE_KEY, new KeyPairParser(new DSAKeyPairParser()));
        parsers.put(TYPE_EC_PRIVATE_KEY, new KeyPairParser(new ECDSAKeyPairParser()));
        parsers.put(TYPE_ENCRYPTED_PRIVATE_KEY, new EncryptedPrivateKeyParser());
        parsers.put(TYPE_PRIVATE_KEY, new PrivateKeyParser());
    }

    /**
     * Read the next PEM object attempting to interpret the header and
     * create a higher level object from the content.
     *
     * @return the next object in the stream, null if no objects left.
     * @throws IOException in case of a parse error.
     */
    public Object readObject()
        throws IOException
    {
        PemObject obj = readPemObject();

        if (obj != null)
        {
            String type = obj.getType();
            Object pemObjectParser = parsers.get(type);
            if (pemObjectParser != null)
            {
                return ((PemObjectParser)pemObjectParser).parseObject(obj);
            }
            else
            {
                throw new IOException("unrecognised object: " + type);
            }
        }

        return null;
    }

    /**
     * @return set of pem object types that can be parsed
     * @see PemObject#getType()
     */
    public Set<String> getSupportedTypes()
    {
        return Collections.unmodifiableSet(parsers.keySet());
    }

    private class KeyPairParser
        implements PemObjectParser
    {
        private final PEMKeyPairParser pemKeyPairParser;

        public KeyPairParser(PEMKeyPairParser pemKeyPairParser)
        {
            this.pemKeyPairParser = pemKeyPairParser;
        }

        /**
         * Read a Key Pair
         */
        public Object parseObject(
            PemObject obj)
            throws IOException
        {
            boolean isEncrypted = false;
            String dekInfo = null;
            List headers = obj.getHeaders();

            for (Iterator it = headers.iterator(); it.hasNext();)
            {
                PemHeader hdr = (PemHeader)it.next();

                if (hdr.getName().equals("Proc-Type") && hdr.getValue().equals("4,ENCRYPTED"))
                {
                    isEncrypted = true;
                }
                else if (hdr.getName().equals("DEK-Info"))
                {
                    dekInfo = hdr.getValue();
                }
            }

            //
            // extract the key
            //
            byte[] keyBytes = obj.getContent();

            try
            {
                if (isEncrypted)
                {
                    StringTokenizer tknz = new StringTokenizer(dekInfo, ",");
                    String dekAlgName = tknz.nextToken();
                    byte[] iv = Hex.decode(tknz.nextToken());

                    return new PEMEncryptedKeyPair(dekAlgName, iv, keyBytes, pemKeyPairParser);
                }

                return pemKeyPairParser.parse(keyBytes);
            }
            catch (IOException e)
            {
                if (isEncrypted)
                {
                    throw new PEMException("exception decoding - please check password and data.", e);
                }
                else
                {
                    throw new PEMException(e.getMessage(), e);
                }
            }
            catch (IllegalArgumentException e)
            {
                if (isEncrypted)
                {
                    throw new PEMException("exception decoding - please check password and data.", e);
                }
                else
                {
                    throw new PEMException(e.getMessage(), e);
                }
            }
        }
    }

    private class DSAKeyPairParser
        implements PEMKeyPairParser
    {
        public PEMKeyPair parse(byte[] encoding)
            throws IOException
        {
            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(encoding);

                if (seq.size() != 6)
                {
                    throw new PEMException("malformed sequence in DSA private key");
                }

                //            ASN1Integer              v = (ASN1Integer)seq.getObjectAt(0);
                ASN1Integer p = ASN1Integer.getInstance(seq.getObjectAt(1));
                ASN1Integer q = ASN1Integer.getInstance(seq.getObjectAt(2));
                ASN1Integer g = ASN1Integer.getInstance(seq.getObjectAt(3));
                ASN1Integer y = ASN1Integer.getInstance(seq.getObjectAt(4));
                ASN1Integer x = ASN1Integer.getInstance(seq.getObjectAt(5));

                return new PEMKeyPair(
                    new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_dsa, new DSAParameter(p.getValue(), q.getValue(), g.getValue())), y),
                    new PrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(p.getValue(), q.getValue(), g.getValue())), x));
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating DSA private key: " + e.toString(), e);
            }
        }
    }

    private class ECDSAKeyPairParser
        implements PEMKeyPairParser
    {
        public PEMKeyPair parse(byte[] encoding)
            throws IOException
        {
            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(encoding);

                sec.ECPrivateKey pKey = sec.ECPrivateKey.getInstance(seq);
                AlgorithmIdentifier algId = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    pKey.getParametersObject());
                PrivateKeyInfo privInfo = new PrivateKeyInfo(algId, pKey);

                if (pKey.getPublicKey() != null)
                {
                    SubjectPublicKeyInfo pubInfo = new SubjectPublicKeyInfo(algId, pKey.getPublicKey().getBytes());

                    return new PEMKeyPair(pubInfo, privInfo);
                }
                else
                {
                    return new PEMKeyPair(null, privInfo);
                }
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating EC private key: " + e.toString(), e);
            }
        }
    }

    private class RSAKeyPairParser
        implements PEMKeyPairParser
    {
        public PEMKeyPair parse(byte[] encoding)
            throws IOException
        {
            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(encoding);

                if (seq.size() != 9)
                {
                    throw new PEMException("malformed sequence in RSA private key");
                }

                RSAPrivateKey keyStruct = RSAPrivateKey.getInstance(seq);

                RSAPublicKey pubSpec = new RSAPublicKey(
                    keyStruct.getModulus(), keyStruct.getPublicExponent());

                AlgorithmIdentifier algId = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);

                return new PEMKeyPair(new SubjectPublicKeyInfo(algId, pubSpec), new PrivateKeyInfo(algId, keyStruct));
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException(
                    "problem creating RSA private key: " + e.toString(), e);
            }
        }
    }

    private class PublicKeyParser
        implements PemObjectParser
    {
        public PublicKeyParser()
        {
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            return SubjectPublicKeyInfo.getInstance(obj.getContent());
        }
    }

    private class RSAPublicKeyParser
        implements PemObjectParser
    {
        public RSAPublicKeyParser()
        {
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                RSAPublicKey rsaPubStructure = RSAPublicKey.getInstance(obj.getContent());

                return new SubjectPublicKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE), rsaPubStructure);
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException("problem extracting key: " + e.toString(), e);
            }
        }
    }

    private class X509CertificateParser
        implements PemObjectParser
    {
        /**
         * Reads in a X509Certificate.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return new X509CertificateHolder(obj.getContent());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class X509TrustedCertificateParser
        implements PemObjectParser
    {
        /**
         * Reads in a X509Certificate.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return new X509TrustedCertificateBlock(obj.getContent());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class X509CRLParser
        implements PemObjectParser
    {
        /**
         * Reads in a X509CRL.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return new X509CRLHolder(obj.getContent());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing cert: " + e.toString(), e);
            }
        }
    }

    private class PKCS10CertificationRequestParser
        implements PemObjectParser
    {
        /**
         * Reads in a PKCS10 certification request.
         *
         * @return the certificate request.
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return new PKCS10CertificationRequest(obj.getContent());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing certrequest: " + e.toString(), e);
            }
        }
    }

    private class PKCS7Parser
        implements PemObjectParser
    {
        /**
         * Reads in a PKCS7 object. This returns a ContentInfo object suitable for use with the CMS
         * API.
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                ASN1InputStream aIn = new ASN1InputStream(obj.getContent());

                return ContentInfo.getInstance(aIn.readObject());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing PKCS7 object: " + e.toString(), e);
            }
        }
    }

    private class X509AttributeCertificateParser
        implements PemObjectParser
    {
        public Object parseObject(PemObject obj)
            throws IOException
        {
            return new X509AttributeCertificateHolder(obj.getContent());
        }
    }

    private class ECCurveParamsParser
        implements PemObjectParser
    {
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                Object param = ASN1Primitive.fromByteArray(obj.getContent());

                if (param instanceof ASN1ObjectIdentifier)
                {
                    return ASN1Primitive.fromByteArray(obj.getContent());
                }
                else if (param instanceof ASN1Sequence)
                {
                    return X9ECParameters.getInstance(param);
                }
                else
                {
                    return null;  // implicitly CA
                }
            }
            catch (IOException e)
            {
                throw e;
            }
            catch (Exception e)
            {
                throw new PEMException("exception extracting EC named curve: " + e.toString());
            }
        }
    }

    private class EncryptedPrivateKeyParser
        implements PemObjectParser
    {
        public EncryptedPrivateKeyParser()
        {
        }

        /**
         * Reads in an EncryptedPrivateKeyInfo
         *
         * @return the X509Certificate
         * @throws IOException if an I/O error occured
         */
        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return new PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo.getInstance(obj.getContent()));
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing ENCRYPTED PRIVATE KEY: " + e.toString(), e);
            }
        }
    }

    private class PrivateKeyParser
        implements PemObjectParser
    {
        public PrivateKeyParser()
        {
        }

        public Object parseObject(PemObject obj)
            throws IOException
        {
            try
            {
                return PrivateKeyInfo.getInstance(obj.getContent());
            }
            catch (Exception e)
            {
                throw new PEMException("problem parsing PRIVATE KEY: " + e.toString(), e);
            }
        }
    }
}