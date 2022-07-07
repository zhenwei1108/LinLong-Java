package com.github.zhenwei.core.crypto;

import com.github.zhenwei.core.crypto.params.AsymmetricKeyParameter;
import java.io.IOException;
import java.io.InputStream;

public interface KeyParser {

  AsymmetricKeyParameter readKey(InputStream stream)
      throws IOException;
}