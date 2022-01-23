package com.github.zhenwei.pkix.openssl;


 
import com.github.zhenwei.core.asn1.ASN1EncodableVector;
import com.github.zhenwei.core.asn1.ASN1Integer;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.DERSequence;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.DSAParameter;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.asn1.x9.X9ObjectIdentifiers;
import com.github.zhenwei.core.util.Strings;
import com.github.zhenwei.core.util.io.pem.PemGenerationException;
import com.github.zhenwei.core.util.io.pem.PemHeader;
import com.github.zhenwei.core.util.io.pem.PemObject;
import com.github.zhenwei.core.util.io.pem.PemObjectGenerator;
import com.github.zhenwei.pkix.cert.X509AttributeCertificateHolder;
import com.github.zhenwei.pkix.cert.X509CRLHolder;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
 
 






 


/**
 * PEM generator for the original set of PEM objects used in Open SSL.
 */
public class MiscPEMGenerator
    implements PemObjectGenerator
{
    private static final ASN1ObjectIdentifier[] dsaOids =
    {
        X9ObjectIdentifiers.id_dsa,
        OIWObjectIdentifiers.dsaWithSHA1
    };

    private static final byte[] hexEncodingTable =
    {
        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
        (byte)'8', (byte)'9', (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F'
    };

    private final Object obj;
    private final PEMEncryptor encryptor;

    public MiscPEMGenerator(Object o)
    {
        this.obj = o;              // use of this confuses some earlier JDKs.
        this.encryptor = null;
    }

    public MiscPEMGenerator(Object o, PEMEncryptor encryptor)
    {
        this.obj = o;
        this.encryptor = encryptor;
    }

    private PemObject createPemObject(Object o)
        throws IOException
    {
        String  type;
        byte[]  encoding;

        if (o instanceof PemObject)
        {
            return (PemObject)o;
        }
        if (o instanceof PemObjectGenerator)
        {
            return ((PemObjectGenerator)o).generate();
        }
        if (o instanceof X509CertificateHolder)
        {
            type = "CERTIFICATE";

            encoding = ((X509CertificateHolder)o).getEncoded();
        }
        else if (o instanceof X509CRLHolder)
        {
            type = "X509 CRL";

            encoding = ((X509CRLHolder)o).getEncoded();
        }
        else if (o instanceof X509TrustedCertificateBlock)
        {
            type = "TRUSTED CERTIFICATE";

            encoding = ((X509TrustedCertificateBlock)o).getEncoded();
        }
        else if (o instanceof PrivateKeyInfo)
        {
            PrivateKeyInfo info = (PrivateKeyInfo)o;
            ASN1ObjectIdentifier algOID = info.getPrivateKeyAlgorithm().getAlgorithm();

            if (algOID.equals(PKCSObjectIdentifiers.rsaEncryption))
            {
                type = "RSA PRIVATE KEY";

                encoding = info.parsePrivateKey().toASN1Primitive().getEncoded();
            }
            else if (algOID.equals(dsaOids[0]) || algOID.equals(dsaOids[1]))
            {
                type = "DSA PRIVATE KEY";

                DSAParameter p = DSAParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
                ASN1EncodableVector v = new ASN1EncodableVector();

                v.add(new ASN1Integer(0));
                v.add(new ASN1Integer(p.getP()));
                v.add(new ASN1Integer(p.getQ()));
                v.add(new ASN1Integer(p.getG()));

                BigInteger x = ASN1Integer.getInstance(info.parsePrivateKey()).getValue();
                BigInteger y = p.getG().modPow(x, p.getP());

                v.add(new ASN1Integer(y));
                v.add(new ASN1Integer(x));

                encoding = new DERSequence(v).getEncoded();
            }
            else if (algOID.equals(X9ObjectIdentifiers.id_ecPublicKey))
            {
                type = "EC PRIVATE KEY";

                encoding = info.parsePrivateKey().toASN1Primitive().getEncoded();
            }
            else
            {
                type = "PRIVATE KEY";

                encoding = info.getEncoded();
            }
        }
        else if (o instanceof SubjectPublicKeyInfo)
        {
            type = "PUBLIC KEY";

            encoding = ((SubjectPublicKeyInfo)o).getEncoded();
        }
        else if (o instanceof X509AttributeCertificateHolder)
        {
            type = "ATTRIBUTE CERTIFICATE";
            encoding = ((X509AttributeCertificateHolder)o).getEncoded();
        }
        else if (o instanceof PKCS10CertificationRequest)
        {
            type = "CERTIFICATE REQUEST";
            encoding = ((PKCS10CertificationRequest)o).getEncoded();
        }
        else if (o instanceof PKCS8EncryptedPrivateKeyInfo)
        {
            type = "ENCRYPTED PRIVATE KEY";
            encoding = ((PKCS8EncryptedPrivateKeyInfo)o).getEncoded();
        }
        else if (o instanceof ContentInfo)
        {
            type = "PKCS7";
            encoding = ((ContentInfo)o).getEncoded();
        }
        else
        {
            throw new PemGenerationException("unknown object passed - can't encode.");
        }

        if (encryptor != null)
        {
            String dekAlgName = Strings.toUpperCase(encryptor.getAlgorithm());

            // Note: For backward compatibility
            if (dekAlgName.equals("DESEDE"))
            {
                dekAlgName = "DES-EDE3-CBC";
            }


            byte[] iv = encryptor.getIV();

            byte[] encData = encryptor.encrypt(encoding);

            List headers = new ArrayList(2);

            headers.add(new PemHeader("Proc-Type", "4,ENCRYPTED"));
            headers.add(new PemHeader("DEK-Info", dekAlgName + "," + getHexEncoded(iv)));

            return new PemObject(type, headers, encData);
        }
        return new PemObject(type, encoding);
    }

    private String getHexEncoded(byte[] bytes)
        throws IOException
    {
        char[] chars = new char[bytes.length * 2];

        for (int i = 0; i != bytes.length; i++)
        {
            int    v = bytes[i] & 0xff;

            chars[2 * i] = (char)(hexEncodingTable[(v >>> 4)]);
            chars[2 * i + 1]  = (char)(hexEncodingTable[v & 0xf]);
        }

        return new String(chars);
    }

    public PemObject generate()
        throws PemGenerationException
    {
        try
        {
            return createPemObject(obj);
        }
        catch (IOException e)
        {
            throw new PemGenerationException("encoding exception: " + e.getMessage(), e);
        }
    }
}