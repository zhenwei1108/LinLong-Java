package com.github.zhenwei.pkix.cms.bc;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.oiw.OIWObjectIdentifiers;
import com.github.zhenwei.core.asn1.pkcs.PKCSObjectIdentifiers;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.CipherKeyGenerator;
import com.github.zhenwei.core.crypto.modes.AEADBlockCipher;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.crypto.util.CipherFactory;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.operator.DefaultSecretKeySizeProvider;
import com.github.zhenwei.pkix.operator.GenericKey;
import com.github.zhenwei.pkix.operator.MacCaptureStream;
import com.github.zhenwei.pkix.operator.OutputAEADEncryptor;
import com.github.zhenwei.pkix.operator.OutputEncryptor;
import com.github.zhenwei.pkix.operator.SecretKeySizeProvider;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;

public class BcCMSContentEncryptorBuilder {

  private static final SecretKeySizeProvider KEY_SIZE_PROVIDER = DefaultSecretKeySizeProvider.INSTANCE;

  private final ASN1ObjectIdentifier encryptionOID;
  private final int keySize;

  private EnvelopedDataHelper helper = new EnvelopedDataHelper();
  private SecureRandom random;

  public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID) {
    this(encryptionOID, KEY_SIZE_PROVIDER.getKeySize(encryptionOID));
  }

  public BcCMSContentEncryptorBuilder(ASN1ObjectIdentifier encryptionOID, int keySize) {
    this.encryptionOID = encryptionOID;
    int fixedSize = KEY_SIZE_PROVIDER.getKeySize(encryptionOID);

    if (encryptionOID.equals(PKCSObjectIdentifiers.des_EDE3_CBC)) {
      if (keySize != 168 && keySize != fixedSize) {
        throw new IllegalArgumentException(
            "incorrect keySize for encryptionOID passed to builder.");
      }
      this.keySize = 168;
    } else if (encryptionOID.equals(OIWObjectIdentifiers.desCBC)) {
      if (keySize != 56 && keySize != fixedSize) {
        throw new IllegalArgumentException(
            "incorrect keySize for encryptionOID passed to builder.");
      }
      this.keySize = 56;
    } else {
      if (fixedSize > 0 && fixedSize != keySize) {
        throw new IllegalArgumentException(
            "incorrect keySize for encryptionOID passed to builder.");
      }
      this.keySize = keySize;
    }
  }

  public BcCMSContentEncryptorBuilder setSecureRandom(SecureRandom random) {
    this.random = random;

    return this;
  }

  public OutputEncryptor build()
      throws CMSException {
    if (helper.isAuthEnveloped(encryptionOID)) {
      return new CMSAuthOutputEncryptor(encryptionOID, keySize, random);
    }
    return new CMSOutputEncryptor(encryptionOID, keySize, random);
  }

  private class CMSOutputEncryptor
      implements OutputEncryptor {

    private KeyParameter encKey;
    private AlgorithmIdentifier algorithmIdentifier;
    protected Object cipher;

    CMSOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
        throws CMSException {
      if (random == null) {
        random = new SecureRandom();
      }

      CipherKeyGenerator keyGen = helper.createKeyGenerator(encryptionOID, keySize, random);

      encKey = new KeyParameter(keyGen.generateKey());

      algorithmIdentifier = helper.generateEncryptionAlgID(encryptionOID, encKey, random);

      cipher = EnvelopedDataHelper.createContentCipher(true, encKey, algorithmIdentifier);
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algorithmIdentifier;
    }

    public OutputStream getOutputStream(OutputStream dOut) {
      return CipherFactory.createOutputStream(dOut, cipher);
    }

    public GenericKey getKey() {
      return new GenericKey(algorithmIdentifier, encKey.getKey());
    }
  }

  private class CMSAuthOutputEncryptor
      extends CMSOutputEncryptor
      implements OutputAEADEncryptor {

    private AEADBlockCipher aeadCipher;
    private MacCaptureStream macOut;

    CMSAuthOutputEncryptor(ASN1ObjectIdentifier encryptionOID, int keySize, SecureRandom random)
        throws CMSException {
      super(encryptionOID, keySize, random);

      aeadCipher = getCipher();
    }

    private AEADBlockCipher getCipher() {
      if (!(cipher instanceof AEADBlockCipher)) {
        throw new IllegalArgumentException(
            "Unable to create Authenticated Output Encryptor without Authenticaed Data cipher!");
      }
      return (AEADBlockCipher) cipher;
    }

    public OutputStream getOutputStream(OutputStream dOut) {
      macOut = new MacCaptureStream(dOut, aeadCipher.getMac().length);
      return CipherFactory.createOutputStream(macOut, cipher);
    }

    public OutputStream getAADStream() {
      return new AADStream(aeadCipher);
    }

    public byte[] getMAC() {
      return macOut.getMac();
    }
  }

  private static class AADStream
      extends OutputStream {

    private AEADBlockCipher cipher;

    public AADStream(AEADBlockCipher cipher) {
      this.cipher = cipher;
    }

    public void write(byte[] buf, int off, int len)
        throws IOException {
      cipher.processAADBytes(buf, off, len);
    }

    public void write(int b)
        throws IOException {
      cipher.processAADByte((byte) b);
    }
  }
}