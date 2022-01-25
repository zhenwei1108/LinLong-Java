package com.github.zhenwei.pkix.cms.jcajce;

import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.pkix.cert.X509CertificateHolder;
import com.github.zhenwei.pkix.cert.jcajce.JcaX509CertificateHolder;
import com.github.zhenwei.pkix.cms.CMSAttributeTableGenerator;
import com.github.zhenwei.pkix.cms.DefaultSignedAttributeTableGenerator;
import com.github.zhenwei.pkix.cms.SignerInfoGenerator;
import com.github.zhenwei.pkix.cms.SignerInfoGeneratorBuilder;
import com.github.zhenwei.pkix.operator.ContentSigner;
import com.github.zhenwei.pkix.operator.DigestCalculatorProvider;
import com.github.zhenwei.pkix.operator.OperatorCreationException;
import com.github.zhenwei.pkix.operator.jcajce.JcaContentSignerBuilder;
import com.github.zhenwei.pkix.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import com.github.zhenwei.pkix.util.asn1.cms.AttributeTable;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Use this class if you are using a provider that has all the facilities you need.
 * <p>
 * For example:
 * <pre>
 *      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
 *      ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());
 *
 *      gen.addSignerInfoGenerator(
 *                new JcaSignerInfoGeneratorBuilder(
 *                     new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
 *                     .build(sha1Signer, signCert));
 * </pre>
 * becomes:
 * <pre>
 *      CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
 *
 *      gen.addSignerInfoGenerator(
 *                new JcaSimpleSignerInfoGeneratorBuilder()
 *                     .setProvider("BC")
 *                     .build("SHA1withRSA", signKP.getPrivate(), signCert));
 * </pre>
 */
public class JcaSimpleSignerInfoGeneratorBuilder {

  private Helper helper;

  private boolean hasNoSignedAttributes;
  private CMSAttributeTableGenerator signedGen;
  private CMSAttributeTableGenerator unsignedGen;
  private AlgorithmIdentifier contentDigest;

  public JcaSimpleSignerInfoGeneratorBuilder()
      throws OperatorCreationException {
    this.helper = new Helper();
  }

  public JcaSimpleSignerInfoGeneratorBuilder setProvider(String providerName)
      throws OperatorCreationException {
    this.helper = new NamedHelper(providerName);

    return this;
  }

  public JcaSimpleSignerInfoGeneratorBuilder setProvider(Provider provider)
      throws OperatorCreationException {
    this.helper = new ProviderHelper(provider);

    return this;
  }

  /**
   * If the passed in flag is true, the signer signature will be based on the data, not a collection
   * of signed attributes, and no signed attributes will be included.
   *
   * @return the builder object
   */
  public JcaSimpleSignerInfoGeneratorBuilder setDirectSignature(boolean hasNoSignedAttributes) {
    this.hasNoSignedAttributes = hasNoSignedAttributes;

    return this;
  }

  public JcaSimpleSignerInfoGeneratorBuilder setContentDigest(AlgorithmIdentifier contentDigest) {
    this.contentDigest = contentDigest;

    return this;
  }

  public JcaSimpleSignerInfoGeneratorBuilder setSignedAttributeGenerator(
      CMSAttributeTableGenerator signedGen) {
    this.signedGen = signedGen;

    return this;
  }

  /**
   * set up a DefaultSignedAttributeTableGenerator primed with the passed in AttributeTable.
   *
   * @param attrTable table of attributes for priming generator
   * @return this.
   */
  public JcaSimpleSignerInfoGeneratorBuilder setSignedAttributeGenerator(AttributeTable attrTable) {
    this.signedGen = new DefaultSignedAttributeTableGenerator(attrTable);

    return this;
  }

  public JcaSimpleSignerInfoGeneratorBuilder setUnsignedAttributeGenerator(
      CMSAttributeTableGenerator unsignedGen) {
    this.unsignedGen = unsignedGen;

    return this;
  }

  public SignerInfoGenerator build(String algorithmName, PrivateKey privateKey,
      X509CertificateHolder certificate)
      throws OperatorCreationException {
    privateKey = CMSUtils.cleanPrivateKey(privateKey);
    ContentSigner contentSigner = helper.createContentSigner(algorithmName, privateKey);

    return configureAndBuild().build(contentSigner, certificate);
  }

  public SignerInfoGenerator build(String algorithmName, PrivateKey privateKey,
      X509Certificate certificate)
      throws OperatorCreationException, CertificateEncodingException {
    privateKey = CMSUtils.cleanPrivateKey(privateKey);
    ContentSigner contentSigner = helper.createContentSigner(algorithmName, privateKey);

    return configureAndBuild().build(contentSigner, new JcaX509CertificateHolder(certificate));
  }

  public SignerInfoGenerator build(String algorithmName, PrivateKey privateKey,
      byte[] keyIdentifier)
      throws OperatorCreationException {
    privateKey = CMSUtils.cleanPrivateKey(privateKey);
    ContentSigner contentSigner = helper.createContentSigner(algorithmName, privateKey);

    return configureAndBuild().build(contentSigner, keyIdentifier);
  }

  private SignerInfoGeneratorBuilder configureAndBuild()
      throws OperatorCreationException {
    SignerInfoGeneratorBuilder infoGeneratorBuilder = new SignerInfoGeneratorBuilder(
        helper.createDigestCalculatorProvider());

    infoGeneratorBuilder.setDirectSignature(hasNoSignedAttributes);
    infoGeneratorBuilder.setContentDigest(contentDigest);
    infoGeneratorBuilder.setSignedAttributeGenerator(signedGen);
    infoGeneratorBuilder.setUnsignedAttributeGenerator(unsignedGen);

    return infoGeneratorBuilder;
  }

  private class Helper {

    ContentSigner createContentSigner(String algorithm, PrivateKey privateKey)
        throws OperatorCreationException {
      privateKey = CMSUtils.cleanPrivateKey(privateKey);
      return new JcaContentSignerBuilder(algorithm).build(privateKey);
    }

    DigestCalculatorProvider createDigestCalculatorProvider()
        throws OperatorCreationException {
      return new JcaDigestCalculatorProviderBuilder().build();
    }
  }

  private class NamedHelper
      extends Helper {

    private final String providerName;

    public NamedHelper(String providerName) {
      this.providerName = providerName;
    }

    ContentSigner createContentSigner(String algorithm, PrivateKey privateKey)
        throws OperatorCreationException {
      privateKey = CMSUtils.cleanPrivateKey(privateKey);
      return new JcaContentSignerBuilder(algorithm).setProvider(providerName).build(privateKey);
    }

    DigestCalculatorProvider createDigestCalculatorProvider()
        throws OperatorCreationException {
      return new JcaDigestCalculatorProviderBuilder().setProvider(providerName).build();
    }
  }

  private class ProviderHelper
      extends Helper {

    private final Provider provider;

    public ProviderHelper(Provider provider) {
      this.provider = provider;
    }

    ContentSigner createContentSigner(String algorithm, PrivateKey privateKey)
        throws OperatorCreationException {
      privateKey = CMSUtils.cleanPrivateKey(privateKey);
      return new JcaContentSignerBuilder(algorithm).setProvider(provider).build(privateKey);
    }

    DigestCalculatorProvider createDigestCalculatorProvider()
        throws OperatorCreationException {
      return new JcaDigestCalculatorProviderBuilder().setProvider(provider).build();
    }
  }
}