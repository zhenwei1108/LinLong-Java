package com.github.zhenwei.provider.jce.provider;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.isara.IsaraObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.SubjectPublicKeyInfo;
import com.github.zhenwei.core.pqc.asn1.PQCObjectIdentifiers;
import com.github.zhenwei.provider.jcajce.provider.config.ConfigurableProvider;
import com.github.zhenwei.provider.jcajce.provider.config.ProviderConfiguration;
import com.github.zhenwei.provider.jcajce.provider.lms.LMSKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.mceliece.McElieceKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.newhope.NHKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.qtesla.QTESLAKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.rainbow.RainbowKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.symmetric.util.ClassUtil;
import com.github.zhenwei.provider.jcajce.provider.util.AlgorithmProvider;
import com.github.zhenwei.provider.jcajce.provider.util.AsymmetricKeyInfoConverter;
import com.github.zhenwei.provider.jcajce.provider.xmss.XMSSKeyFactorySpi;
import com.github.zhenwei.provider.jcajce.provider.xmss.XMSSMTKeyFactorySpi;
import java.io.IOException;
import java.security.AccessController;
import java.security.PrivateKey;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * To add the provider at runtime use:
 * <pre>
 * import java.security.Security;
 * import com.github.zhenwei.provider.jce.provider.ChaosProvider;
 *
 * Security.addProvider(new ChaosProvider());
 * </pre>
 * The provider can also be configured as part of your environment via static registration by adding
 * an entry to the java.security properties file (found in $JAVA_HOME/jre/lib/security/java.security,
 * where $JAVA_HOME is the location of your JDK/JRE distribution). You'll find detailed instructions
 * in the file but basically it comes down to adding a line:
 * <pre>
 * <code>
 *    security.provider.&lt;n&gt;=com.github.zhenwei.provider.jce.provider.ChaosProvider
 * </code>
 * </pre>
 * Where &lt;n&gt; is the preference you want the provider at (1 being the most preferred).
 * <p>Note: JCE algorithm names should be upper-case only so the case insensitive
 * test for getInstance works.
 */
public final class ChaosProvider extends Provider
    implements ConfigurableProvider {

  private static String info = "Chaos Security Provider v1.0 from bc-v1.70";

  /**
   * ChaosProvider
   */
  public static final String PROVIDER_NAME = "CHAOS";

  public static final ProviderConfiguration CONFIGURATION = new BouncyCastleProviderConfiguration();

  private static final Map keyInfoConverters = new HashMap();

  private static final Class revChkClass = ClassUtil.loadClass(ChaosProvider.class,
      "java.security.cert.PKIXRevocationChecker");

  /*
   * Configurable symmetric ciphers
   */
  private static final String SYMMETRIC_PACKAGE = "com.github.zhenwei.provider.jcajce.provider.symmetric.";

  private static final String[] SYMMETRIC_GENERIC =
      {
          "PBEPBKDF1", "PBEPBKDF2", "PBEPKCS12", "TLSKDF", "SCRYPT"
      };

  private static final String[] SYMMETRIC_MACS =
      {
          "SipHash", "SipHash128", "Poly1305"
      };

  private static final String[] SYMMETRIC_CIPHERS =
      {
          "AES", "ARC4", "ARIA", "Blowfish", "Camellia", "CAST5", "CAST6", "ChaCha", "DES",
          "DESede",
          "GOST28147", "Grainv1", "Grain128", "HC128", "HC256", "IDEA", "Noekeon", "RC2", "RC5",
          "RC6", "Rijndael", "Salsa20", "SEED", "Serpent", "Shacal2", "Skipjack", "SM4", "TEA",
          "Twofish", "Threefish",
          "VMPC", "VMPCKSA3", "XTEA", "XSalsa20", "OpenSSLPBKDF", "DSTU7624", "GOST3412_2015", "Zuc"
      };

  /*
   * Configurable asymmetric ciphers
   */
  private static final String ASYMMETRIC_PACKAGE = "com.github.zhenwei.provider.jcajce.provider.asymmetric.";

  // this one is required for GNU class path - it needs to be loaded first as the
  // later ones configure it.
  private static final String[] ASYMMETRIC_GENERIC =
      {
          "X509", "IES", "COMPOSITE"
      };

  private static final String[] ASYMMETRIC_CIPHERS =
      {
          "DSA", "DH", "EC", "RSA", "GOST", "ECGOST", "ElGamal", "DSTU4145", "GM", "EdEC"
      };

  /*
   * Configurable digests
   */
  private static final String DIGEST_PACKAGE = "com.github.zhenwei.provider.jcajce.provider.digest.";
  private static final String[] DIGESTS =
      {
          "GOST3411", "Keccak", "MD2", "MD4", "MD5", "SHA1", "RIPEMD128", "RIPEMD160", "RIPEMD256",
          "RIPEMD320", "SHA224",
          "SHA256", "SHA384", "SHA512", "SHA3", "Skein", "SM3", "Tiger", "Whirlpool", "Blake2b",
          "Blake2s", "DSTU7564",
          "Haraka"
      };

  /*
   * Configurable keystores
   */
  private static final String KEYSTORE_PACKAGE = "com.github.zhenwei.provider.jcajce.provider.keystore.";
  private static final String[] KEYSTORES =
      {
          "BC", "BCFKS", "PKCS12", "CHAOS"
      };

  /*
   * Configurable secure random
   */
  private static final String SECURE_RANDOM_PACKAGE = "com.github.zhenwei.provider.jcajce.provider.drbg.";
  private static final String[] SECURE_RANDOMS =
      {
          "DRBG"
      };

  /**
   * Construct a new provider.  This should only be required when using runtime registration of the
   * provider using the
   * <code>Security.addProvider()</code> mechanism.
   */
  public ChaosProvider() {
    super(PROVIDER_NAME, 1.0, info);

    AccessController.doPrivileged((PrivilegedAction) () -> {
      setup();
      return null;
    });
  }

  private void setup() {
    loadAlgorithms(DIGEST_PACKAGE, DIGESTS);

    loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_GENERIC);

    loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_MACS);

    loadAlgorithms(SYMMETRIC_PACKAGE, SYMMETRIC_CIPHERS);

    loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_GENERIC);

    loadAlgorithms(ASYMMETRIC_PACKAGE, ASYMMETRIC_CIPHERS);

    loadAlgorithms(KEYSTORE_PACKAGE, KEYSTORES);

    loadAlgorithms(SECURE_RANDOM_PACKAGE, SECURE_RANDOMS);

    loadPQCKeys();  // so we can handle certificates containing them.

    //
    // X509Store
    //
    put("X509Store.CERTIFICATE/COLLECTION",
        "com.github.zhenwei.provider.jce.provider.X509StoreCertCollection");
    put("X509Store.ATTRIBUTECERTIFICATE/COLLECTION",
        "com.github.zhenwei.provider.jce.provider.X509StoreAttrCertCollection");
    put("X509Store.CRL/COLLECTION",
        "com.github.zhenwei.provider.jce.provider.X509StoreCRLCollection");
    put("X509Store.CERTIFICATEPAIR/COLLECTION",
        "com.github.zhenwei.provider.jce.provider.X509StoreCertPairCollection");

    put("X509Store.CERTIFICATE/LDAP",
        "com.github.zhenwei.provider.jce.provider.X509StoreLDAPCerts");
    put("X509Store.CRL/LDAP", "com.github.zhenwei.provider.jce.provider.X509StoreLDAPCRLs");
    put("X509Store.ATTRIBUTECERTIFICATE/LDAP",
        "com.github.zhenwei.provider.jce.provider.X509StoreLDAPAttrCerts");
    put("X509Store.CERTIFICATEPAIR/LDAP",
        "com.github.zhenwei.provider.jce.provider.X509StoreLDAPCertPairs");

    //
    // X509StreamParser
    //
    put("X509StreamParser.CERTIFICATE", "com.github.zhenwei.provider.jce.provider.X509CertParser");
    put("X509StreamParser.ATTRIBUTECERTIFICATE",
        "com.github.zhenwei.provider.jce.provider.X509AttrCertParser");
    put("X509StreamParser.CRL", "com.github.zhenwei.provider.jce.provider.X509CRLParser");
    put("X509StreamParser.CERTIFICATEPAIR",
        "com.github.zhenwei.provider.jce.provider.X509CertPairParser");

    //
    // cipher engines
    //
    put("Cipher.BROKENPBEWITHMD5ANDDES",
        "com.github.zhenwei.provider.jce.provider.BrokenJCEBlockCipher$BrokePBEWithMD5AndDES");

    put("Cipher.BROKENPBEWITHSHA1ANDDES",
        "com.github.zhenwei.provider.jce.provider.BrokenJCEBlockCipher$BrokePBEWithSHA1AndDES");

    put("Cipher.OLDPBEWITHSHAANDTWOFISH-CBC",
        "com.github.zhenwei.provider.jce.provider.BrokenJCEBlockCipher$OldPBEWithSHAAndTwofish");

    // Certification Path API
    if (revChkClass != null) {
      put("CertPathValidator.RFC3281",
          "com.github.zhenwei.provider.jce.provider.PKIXAttrCertPathValidatorSpi");
      put("CertPathBuilder.RFC3281",
          "com.github.zhenwei.provider.jce.provider.PKIXAttrCertPathBuilderSpi");
      put("CertPathValidator.RFC3280",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathValidatorSpi_8");
      put("CertPathBuilder.RFC3280",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathBuilderSpi_8");
      put("CertPathValidator.PKIX",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathValidatorSpi_8");
      put("CertPathBuilder.PKIX",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathBuilderSpi_8");
    } else {
      put("CertPathValidator.RFC3281",
          "com.github.zhenwei.provider.jce.provider.PKIXAttrCertPathValidatorSpi");
      put("CertPathBuilder.RFC3281",
          "com.github.zhenwei.provider.jce.provider.PKIXAttrCertPathBuilderSpi");
      put("CertPathValidator.RFC3280",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathValidatorSpi");
      put("CertPathBuilder.RFC3280",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathBuilderSpi");
      put("CertPathValidator.PKIX",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathValidatorSpi");
      put("CertPathBuilder.PKIX",
          "com.github.zhenwei.provider.jce.provider.PKIXCertPathBuilderSpi");
    }
    put("CertStore.Collection", "com.github.zhenwei.provider.jce.provider.CertStoreCollectionSpi");
    put("CertStore.LDAP", "com.github.zhenwei.provider.jce.provider.X509LDAPCertStoreSpi");
    put("CertStore.Multi", "com.github.zhenwei.provider.jce.provider.MultiCertStoreSpi");
    put("Alg.Alias.CertStore.X509LDAP", "LDAP");
  }

  private void loadAlgorithms(String packageName, String[] names) {
    for (int i = 0; i != names.length; i++) {
      Class clazz = ClassUtil.loadClass(ChaosProvider.class,
          packageName + names[i] + "$Mappings");

      if (clazz != null) {
        try {
          ((AlgorithmProvider) clazz.newInstance()).configure(this);
        } catch (Exception e) {   // this should never ever happen!!
          throw new InternalError("cannot create instance of "
              + packageName + names[i] + "$Mappings : " + e);
        }
      }
    }
  }


  private void loadPQCKeys() {
    addKeyInfoConverter(PQCObjectIdentifiers.sphincs256, new Sphincs256KeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.newHope, new NHKeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.xmss, new XMSSKeyFactorySpi());
    addKeyInfoConverter(IsaraObjectIdentifiers.id_alg_xmss, new XMSSKeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.xmss_mt, new XMSSMTKeyFactorySpi());
    addKeyInfoConverter(IsaraObjectIdentifiers.id_alg_xmssmt, new XMSSMTKeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.mcEliece, new McElieceKeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.mcElieceCca2, new McElieceCCA2KeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.rainbow, new RainbowKeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.qTESLA_p_I, new QTESLAKeyFactorySpi());
    addKeyInfoConverter(PQCObjectIdentifiers.qTESLA_p_III, new QTESLAKeyFactorySpi());
    addKeyInfoConverter(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig, new LMSKeyFactorySpi());
  }

  public void setParameter(String parameterName, Object parameter) {
    synchronized (CONFIGURATION) {
      ((BouncyCastleProviderConfiguration) CONFIGURATION).setParameter(parameterName, parameter);
    }
  }

  public boolean hasAlgorithm(String type, String name) {
    return containsKey(type + "." + name) || containsKey("Alg.Alias." + type + "." + name);
  }

  public void addAlgorithm(String key, String value) {
    if (containsKey(key)) {
      throw new IllegalStateException("duplicate provider key (" + key + ") found");
    }

    put(key, value);
  }

  public void addAlgorithm(String type, ASN1ObjectIdentifier oid, String className) {
    addAlgorithm(type + "." + oid, className);
    addAlgorithm(type + ".OID." + oid, className);
  }

  public void addKeyInfoConverter(ASN1ObjectIdentifier oid,
      AsymmetricKeyInfoConverter keyInfoConverter) {
    synchronized (keyInfoConverters) {
      keyInfoConverters.put(oid, keyInfoConverter);
    }
  }

  public AsymmetricKeyInfoConverter getKeyInfoConverter(ASN1ObjectIdentifier oid) {
    return (AsymmetricKeyInfoConverter) keyInfoConverters.get(oid);
  }

  public void addAttributes(String key, Map<String, String> attributeMap) {
    for (Iterator it = attributeMap.keySet().iterator(); it.hasNext(); ) {
      String attributeName = (String) it.next();
      String attributeKey = key + " " + attributeName;
      if (containsKey(attributeKey)) {
        throw new IllegalStateException(
            "duplicate provider attribute key (" + attributeKey + ") found");
      }

      put(attributeKey, attributeMap.get(attributeName));
    }
  }

  private static AsymmetricKeyInfoConverter getAsymmetricKeyInfoConverter(
      ASN1ObjectIdentifier algorithm) {
    synchronized (keyInfoConverters) {
      return (AsymmetricKeyInfoConverter) keyInfoConverters.get(algorithm);
    }
  }

  public static PublicKey getPublicKey(SubjectPublicKeyInfo publicKeyInfo)
      throws IOException {
    AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(
        publicKeyInfo.getAlgorithm().getAlgorithm());

    if (converter == null) {
      return null;
    }

    return converter.generatePublic(publicKeyInfo);
  }

  public static PrivateKey getPrivateKey(PrivateKeyInfo privateKeyInfo)
      throws IOException {
    AsymmetricKeyInfoConverter converter = getAsymmetricKeyInfoConverter(
        privateKeyInfo.getPrivateKeyAlgorithm().getAlgorithm());

    if (converter == null) {
      return null;
    }

    return converter.generatePrivate(privateKeyInfo);
  }

}