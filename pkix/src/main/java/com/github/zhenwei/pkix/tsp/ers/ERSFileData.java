package com.github.zhenwei.pkix.tsp.ers;

import com.github.zhenwei.pkix.operator.DigestCalculator;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

/**
 * Generic class for holding a File of data for RFC 4998 ERS.
 */
public class ERSFileData
    extends ERSCachingData {

  private final File content;

  public ERSFileData(File content)
      throws FileNotFoundException {
    if (content.isDirectory()) {
      throw new IllegalArgumentException("directory not allowed as ERSFileData");
    }
    if (!content.exists()) {
      throw new FileNotFoundException(content.getAbsolutePath() + " does not exist");
    }
    if (!content.canRead()) {
      throw new FileNotFoundException(content.getAbsolutePath() + " is not readable");
    }
    this.content = content;
  }

  protected byte[] calculateHash(DigestCalculator digestCalculator) {
    try {
      InputStream contentStream = new FileInputStream(content);
      byte[] hash = ERSUtil.calculateDigest(digestCalculator, contentStream);
      contentStream.close();

      return hash;
    } catch (IOException e) {
      throw new IllegalStateException("unable to process " + content.getAbsolutePath());
    }
  }
}