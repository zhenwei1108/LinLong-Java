package com.github.zhenwei.provider.jcajce.provider.asymmetric.edec;


import com.github.zhenwei.core.asn1.ASN1Encoding;
import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.ASN1Sequence;
import com.github.zhenwei.core.asn1.edec.EdECObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;

import  SubjectPublicKeyInfo;
import com.github.zhenwei.core.crypto.CipherParameters;
import com.github.zhenwei.core.crypto.params.Ed25519PrivateKeyParameters;
import com.github.zhenwei.core.util.Arrays;
import com.github.zhenwei.core.util.encoders.Hex;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
 
 
 
 
import OpenSSHPrivateKeyUtil;
import OpenSSHPublicKeyUtil;
import  interfaces.EdDSAPublicKey;
import  interfaces.XDHPublicKey;
import util.BaseKeyFactorySpi;
 
import  spec.OpenSSHPrivateKeySpec;
import  spec.OpenSSHPublicKeySpec;
import  spec.RawEncodedKeySpec;


 

public class KeyFactorySpi
    extends BaseKeyFactorySpi
    implements AsymmetricKeyInfoConverter
{
    static final byte[] x448Prefix = Hex.decode("3042300506032b656f033900");
    static final byte[] x25519Prefix = Hex.decode("302a300506032b656e032100");
    static final byte[] Ed448Prefix = Hex.decode("3043300506032b6571033a00");
    static final byte[] Ed25519Prefix = Hex.decode("302a300506032b6570032100");

    private static final byte x448_type = 0x6f;
    private static final byte x25519_type = 0x6e;
    private static final byte Ed448_type = 0x71;
    private static final byte Ed25519_type = 0x70;

    String algorithm;
    private final boolean isXdh;
    private final int specificBase;

    public KeyFactorySpi(
        String algorithm,
        boolean isXdh,
        int specificBase)
    {
        this.algorithm = algorithm;
        this.isXdh = isXdh;
        this.specificBase = specificBase;
    }

    protected Key engineTranslateKey(
        Key key)
        throws InvalidKeyException
    {
        throw new InvalidKeyException("key type unknown");
    }

    protected KeySpec engineGetKeySpec(
        Key key,
        Class spec)
        throws InvalidKeySpecException
    {
        if (spec.isAssignableFrom(OpenSSHPrivateKeySpec.class) && key instanceof BCEdDSAPrivateKey)
        {
            try
            {
                //
                // The DEROctetString at element 2 is an encoded DEROctetString with the private key value
                // within it.
                //

                ASN1Sequence seq = ASN1Sequence.getInstance(key.getEncoded());
                ASN1OctetString val = ASN1OctetString.getInstance(seq.getObjectAt(2));
                byte[] encoding = ASN1OctetString.getInstance(ASN1Primitive.fromByteArray(val.getOctets())).getOctets();
                return new OpenSSHPrivateKeySpec(OpenSSHPrivateKeyUtil.encodePrivateKey(new Ed25519PrivateKeyParameters(encoding)));
            }
            catch (IOException ex)
            {
                throw new InvalidKeySpecException(ex.getMessage(), ex.getCause());
            }

        }
        else if (spec.isAssignableFrom(OpenSSHPublicKeySpec.class) && key instanceof BCEdDSAPublicKey)
        {
            try
            {
                byte[] encoding = key.getEncoded();

                if (!Arrays.areEqual(Ed25519Prefix, 0, Ed25519Prefix.length,
                    encoding, 0, encoding.length - Ed25519PublicKeyParameters.KEY_SIZE))
                {
                    throw new InvalidKeySpecException("Invalid Ed25519 public key encoding");
                }

                Ed25519PublicKeyParameters publicKey = new Ed25519PublicKeyParameters(encoding, Ed25519Prefix.length);
                return new OpenSSHPublicKeySpec(OpenSSHPublicKeyUtil.encodePublicKey(publicKey));
            }
            catch (IOException ex)
            {
                throw new InvalidKeySpecException(ex.getMessage(), ex.getCause());
            }
        }
        else if (spec.isAssignableFrom(RawEncodedKeySpec.class))
        {
            if (key instanceof XDHPublicKey)
            {
                return new RawEncodedKeySpec(((XDHPublicKey)key).getUEncoding());
            }
            if (key instanceof EdDSAPublicKey)
            {
                return new RawEncodedKeySpec(((EdDSAPublicKey)key).getPointEncoding());
            }
        }
        
        return super.engineGetKeySpec(key, spec);
    }

    protected PrivateKey engineGeneratePrivate(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof OpenSSHPrivateKeySpec)
        {
            CipherParameters parameters = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(((OpenSSHPrivateKeySpec)keySpec).getEncoded());
            if (parameters instanceof Ed25519PrivateKeyParameters)
            {
                return new BCEdDSAPrivateKey((Ed25519PrivateKeyParameters)parameters);
            }
            throw new IllegalStateException("openssh private key not Ed25519 private key");
        }

        return super.engineGeneratePrivate(keySpec);
    }

    protected PublicKey engineGeneratePublic(
        KeySpec keySpec)
        throws InvalidKeySpecException
    {
        if (keySpec instanceof X509EncodedKeySpec)
        {
            byte[] enc = ((X509EncodedKeySpec)keySpec).getEncoded();
            // optimise if we can
            if ((specificBase == 0 || specificBase == enc[8]))
            {
                // watch out for badly placed DER NULL - the default X509Cert will add these!
                if (enc[9] == 0x05 && enc[10] == 0x00)
                {
                    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(enc);

                    keyInfo = new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(keyInfo.getAlgorithm().getAlgorithm()), keyInfo.getPublicKeyData().getBytes());

                    try
                    {
                        enc = keyInfo.getEncoded(ASN1Encoding.DER);
                    }
                    catch (IOException e)
                    {
                        throw new InvalidKeySpecException("attempt to reconstruct key failed: " + e.getMessage());
                    }
                }

                switch (enc[8])
                {
                case x448_type:
                    return new BCXDHPublicKey(x448Prefix, enc);
                case x25519_type:
                    return new BCXDHPublicKey(x25519Prefix, enc);
                case Ed448_type:
                    return new BCEdDSAPublicKey(Ed448Prefix, enc);
                case Ed25519_type:
                    return new BCEdDSAPublicKey(Ed25519Prefix, enc);
                default:
                    return super.engineGeneratePublic(keySpec);
                }
            }
        }
        else if (keySpec instanceof RawEncodedKeySpec)
        {
            byte[] enc = ((RawEncodedKeySpec)keySpec).getEncoded();
            switch (specificBase)
            {
            case x448_type:
                return new BCXDHPublicKey(new X448PublicKeyParameters(enc));
            case x25519_type:
                return new BCXDHPublicKey(new X25519PublicKeyParameters(enc));
            case Ed448_type:
                return new BCEdDSAPublicKey(new Ed448PublicKeyParameters(enc));
            case Ed25519_type:
                return new BCEdDSAPublicKey(new Ed25519PublicKeyParameters(enc));
            default:
                throw new InvalidKeySpecException("factory not a specific type, cannot recognise raw encoding");
            }
        }
        else if (keySpec instanceof OpenSSHPublicKeySpec)
        {
            CipherParameters parameters = OpenSSHPublicKeyUtil.parsePublicKey(((OpenSSHPublicKeySpec)keySpec).getEncoded());
            if (parameters instanceof Ed25519PublicKeyParameters)
            {
                return new BCEdDSAPublicKey(new byte[0], ((Ed25519PublicKeyParameters)parameters).getEncoded());
            }

            throw new IllegalStateException("openssh public key not Ed25519 public key");
        }

        return super.engineGeneratePublic(keySpec);
    }

    public PrivateKey generatePrivate(PrivateKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getPrivateKeyAlgorithm().getAlgorithm();

        if (isXdh)
        {
            if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(
                EdECObjectIdentifiers.id_X448))
            {
                return new BCXDHPrivateKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
            {
                return new BCXDHPrivateKey(keyInfo);
            }
        }
        else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
            {
                return new BCEdDSAPrivateKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                return new BCEdDSAPrivateKey(keyInfo);
            }
        }

        throw new IOException("algorithm identifier " + algOid + " in key not recognized");
    }

    public PublicKey generatePublic(SubjectPublicKeyInfo keyInfo)
        throws IOException
    {
        ASN1ObjectIdentifier algOid = keyInfo.getAlgorithm().getAlgorithm();

        if (isXdh)
        {
            if ((specificBase == 0 || specificBase == x448_type) && algOid.equals(EdECObjectIdentifiers.id_X448))
            {
                return new BCXDHPublicKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == x25519_type) && algOid.equals(EdECObjectIdentifiers.id_X25519))
            {
                return new BCXDHPublicKey(keyInfo);
            }
        }
        else if (algOid.equals(EdECObjectIdentifiers.id_Ed448) || algOid.equals(EdECObjectIdentifiers.id_Ed25519))
        {
            if ((specificBase == 0 || specificBase == Ed448_type) && algOid.equals(EdECObjectIdentifiers.id_Ed448))
            {
                return new BCEdDSAPublicKey(keyInfo);
            }
            if ((specificBase == 0 || specificBase == Ed25519_type) && algOid.equals(EdECObjectIdentifiers.id_Ed25519))
            {
                return new BCEdDSAPublicKey(keyInfo);
            }
        }

        throw new IOException("algorithm identifier " + algOid + " in key not recognized");
    }

    public static class XDH
        extends edec.KeyFactorySpi
    {
        public XDH()
        {
            super("XDH", true, 0);
        }
    }

    public static class X448
        extends edec.KeyFactorySpi
    {
        public X448()
        {
            super("X448", true, x448_type);
        }
    }

    public static class X25519
        extends edec.KeyFactorySpi
    {
        public X25519()
        {
            super("X25519", true, x25519_type);
        }
    }

    public static class EdDSA
        extends edec.KeyFactorySpi
    {
        public EdDSA()
        {
            super("EdDSA", false, 0);
        }
    }

    public static class Ed448
        extends edec.KeyFactorySpi
    {
        public Ed448()
        {
            super("Ed448", false, Ed448_type);
        }
    }

    public static class Ed25519
        extends edec.KeyFactorySpi
    {
        public Ed25519()
        {
            super("Ed25519", false, Ed25519_type);
        }
    }
}