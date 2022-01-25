package com.github.zhenwei.pkix.cms.bc;

import com.github.zhenwei.core.asn1.ASN1ObjectIdentifier;
import com.github.zhenwei.core.asn1.ASN1OctetString;
import com.github.zhenwei.core.asn1.pkcs.PBKDF2Params;
import com.github.zhenwei.core.asn1.x509.AlgorithmIdentifier;
import com.github.zhenwei.core.crypto.PBEParametersGenerator;
import com.github.zhenwei.core.crypto.Wrapper;
import com.github.zhenwei.core.crypto.generators.PKCS5S2ParametersGenerator;
import com.github.zhenwei.core.crypto.params.KeyParameter;
import com.github.zhenwei.core.crypto.params.ParametersWithIV;
import com.github.zhenwei.pkix.cms.CMSException;
import com.github.zhenwei.pkix.cms.PasswordRecipient;
import com.github.zhenwei.pkix.cms.PasswordRecipientInfoGenerator;
import com.github.zhenwei.pkix.operator.GenericKey;

public class BcPasswordRecipientInfoGenerator
    extends PasswordRecipientInfoGenerator {

  public BcPasswordRecipientInfoGenerator(ASN1ObjectIdentifier kekAlgorithm, char[] password) {
    super(kekAlgorithm, password);
  }

  protected byte[] calculateDerivedKey(int schemeID, AlgorithmIdentifier derivationAlgorithm,
      int keySize)
      throws CMSException {
    PBKDF2Params params = PBKDF2Params.getInstance(derivationAlgorithm.getParameters());
    byte[] encodedPassword =
        (schemeID == PasswordRecipient.PKCS5_SCHEME2) ? PBEParametersGenerator.PKCS5PasswordToBytes(
            password) : PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(password);

    try {
      PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(
          EnvelopedDataHelper.getPRF(params.getPrf()));

      gen.init(encodedPassword, params.getSalt(), params.getIterationCount().intValue());

      return ((KeyParameter) gen.generateDerivedParameters(keySize)).getKey();
    } catch (Exception e) {
      throw new CMSException("exception creating derived key: " + e.getMessage(), e);
    }
  }

  public byte[] generateEncryptedBytes(AlgorithmIdentifier keyEncryptionAlgorithm,
      byte[] derivedKey, GenericKey contentEncryptionKey)
      throws CMSException {
    byte[] contentEncryptionKeySpec = ((KeyParameter) CMSUtils.getBcKey(
        contentEncryptionKey)).getKey();
    Wrapper keyEncryptionCipher = EnvelopedDataHelper.createRFC3211Wrapper(
        keyEncryptionAlgorithm.getAlgorithm());

    keyEncryptionCipher.init(true, new ParametersWithIV(new KeyParameter(derivedKey),
        ASN1OctetString.getInstance(keyEncryptionAlgorithm.getParameters()).getOctets()));

    return keyEncryptionCipher.wrap(contentEncryptionKeySpec, 0, contentEncryptionKeySpec.length);
  }
}