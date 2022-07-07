package com.github.zhenwei.pkix.pkcs;

import com.github.zhenwei.core.asn1.ASN1Primitive;
import com.github.zhenwei.core.asn1.pkcs.EncryptedPrivateKeyInfo;
import com.github.zhenwei.core.asn1.pkcs.PrivateKeyInfo;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.util.io.Streams;
import com.github.zhenwei.pkix.operator.InputDecryptor;
import com.github.zhenwei.pkix.operator.InputDecryptorProvider;
import java.io.ByteArrayInputStream;
import java.io.IOException;

/**
 * Holding class for a PKCS#8 EncryptedPrivateKeyInfo structure.
 */
public class PKCS8EncryptedPrivateKeyInfo {

  private EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;

  private static EncryptedPrivateKeyInfo parseBytes(byte[] pkcs8Encoding)
      throws IOException {
    try {
      return EncryptedPrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(pkcs8Encoding));
    } catch (ClassCastException e) {
      throw new PKCSIOException("malformed data: " + e.getMessage(), e);
    } catch (IllegalArgumentException e) {
      throw new PKCSIOException("malformed data: " + e.getMessage(), e);
    }
  }

  public PKCS8EncryptedPrivateKeyInfo(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo) {
    this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
  }

  public PKCS8EncryptedPrivateKeyInfo(byte[] encryptedPrivateKeyInfo)
      throws IOException {
    this(parseBytes(encryptedPrivateKeyInfo));
  }

  public AlgorithmIdentifier getEncryptionAlgorithm() {
    return encryptedPrivateKeyInfo.getEncryptionAlgorithm();
  }

  public byte[] getEncryptedData() {
    return encryptedPrivateKeyInfo.getEncryptedData();
  }

  public EncryptedPrivateKeyInfo toASN1Structure() {
    return encryptedPrivateKeyInfo;
  }

  public byte[] getEncoded()
      throws IOException {
    return encryptedPrivateKeyInfo.getEncoded();
  }

  public PrivateKeyInfo decryptPrivateKeyInfo(InputDecryptorProvider inputDecryptorProvider)
      throws PKCSException {
    try {
      InputDecryptor decrytor = inputDecryptorProvider.get(
          encryptedPrivateKeyInfo.getEncryptionAlgorithm());

      ByteArrayInputStream encIn = new ByteArrayInputStream(
          encryptedPrivateKeyInfo.getEncryptedData());

      return PrivateKeyInfo.getInstance(Streams.readAll(decrytor.getInputStream(encIn)));
    } catch (Exception e) {
      throw new PKCSException("unable to read encrypted data: " + e.getMessage(), e);
    }
  }
}