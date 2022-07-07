package com.github.zhenwei.pkix.openssl.jcajce;

import com.github.zhenwei.core.util.io.pem.PemGenerationException;
import com.github.zhenwei.core.util.io.pem.PemObjectGenerator;
import com.github.zhenwei.core.util.io.pem.PemWriter;
import com.github.zhenwei.pkix.openssl.PEMEncryptor;
import java.io.IOException;
import java.io.Writer;

/**
 * General purpose writer for OpenSSL PEM objects based on JCA/JCE classes.
 */
public class JcaPEMWriter
    extends PemWriter {

  /**
   * Base constructor.
   *
   * @param out output stream to use.
   */
  public JcaPEMWriter(Writer out) {
    super(out);
  }

  /**
   * @throws IOException
   */
  public void writeObject(
      Object obj)
      throws IOException {
    writeObject(obj, null);
  }

  /**
   * @param obj
   * @param encryptor
   * @throws IOException
   */
  public void writeObject(
      Object obj,
      PEMEncryptor encryptor)
      throws IOException {
    try {
      super.writeObject(new JcaMiscPEMGenerator(obj, encryptor));
    } catch (PemGenerationException e) {
      if (e.getCause() instanceof IOException) {
        throw (IOException) e.getCause();
      }

      throw e;
    }
  }

  public void writeObject(
      PemObjectGenerator obj)
      throws IOException {
    super.writeObject(obj);
  }
}