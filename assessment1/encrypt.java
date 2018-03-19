/*
Student: Sean Healy CPSSD4
Number: 13411482

I declare that this material, which I now submit for assessment, is entirely my
own work and has not been taken from the work of others, save and to the extent that such
work has been acknowledged within the text of my work.
*/

import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class encrypt {
  public static void main(String[] args) {
    int rsaExponent = 65537;
    String publicMod = "c406136c12640a665900a9df4df63a84fc855927b729a3a106fb3f379e8e4190ebba442f67b93402e535b18a5777e6490e67dbee954bb02175e43b6481e7563d3f9ff338f07950d1553ee6c343d3f8148f71b4d2df8da7efb39f846ac07c865201fbb35ea4d71dc5f858d9d41aaa856d50dc2d2732582f80e7d38c32aba87ba9";
    String myPassword = "oWgIWB3Om1rN7oxq";
    byte[] salt = generateKeys();
    byte[] aes256key = sha256(myPassword + DatatypeConverter.printHexBinary(salt));
    byte[] iv = generateKeys();
    byte[] file = readFile(args[0]);
    byte[] aesFile = aesEncryptFile(file, aes256key, iv);
    byte[] rsaOfPw = rsaEncrypt(stringToBytes(myPassword), rsaExponent, publicMod);
    writeFiles(myPassword, "password");
    writeFiles(DatatypeConverter.printHexBinary(rsaOfPw), "password_rsa_encrypted");
    writeFiles(DatatypeConverter.printHexBinary(iv), "iv");
    writeFiles(DatatypeConverter.printHexBinary(salt), "salt");
    writeFiles(DatatypeConverter.printHexBinary(aes256key), "aes_key_not_encrypted");
    writeFiles(DatatypeConverter.printHexBinary(aesFile), "aes_encrypted_zip");
  }

  public static byte[] readFile(String path) {
    try {
      Path fileLocation = Paths.get(path);
      return Files.readAllBytes(fileLocation);
    } catch (IOException e) {
      // exception is a checked exception. I would prefer these errors throw on runtime. So I used RuntimeException in the code.
      throw new RuntimeException(e);
    }
  }

  public static void writeFiles(String fileData, String fileName) {
    try {
      FileOutputStream stream = new FileOutputStream(new File(fileName));
      stream.write(stringToBytes(fileData));
      stream.close();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] stringToBytes(String s) {
    // I found that while writing this s.getBytes kept appearing.
    // after about 3 uses I decided to make it it's own method since the try catch making other bits of code hard to read.
    try {
      return s.getBytes("UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] sha256(String hashMessage) {
    try {
      // Mostly read Java's MessageDigest Documentation to learn how to use it's SHA algorithim
      MessageDigest shaHash = MessageDigest.getInstance("SHA-256");
      byte[] bytes = stringToBytes(hashMessage);
      for (int i = 0; i < 200; i++) {
        bytes = shaHash.digest(bytes);
      }
      return bytes;
    } catch (Exception error) {
      throw new RuntimeException(error);
    }
  }

  public static byte[] generateKeys() {
    // I used this Documentation for how to use the secure random class to generate a 128 bit key
    // https://docs.oracle.com/javase/7/docs/api/java/security/SecureRandom.html
    SecureRandom random = new SecureRandom();
    byte[] bytes = new byte[16];
    random.nextBytes(bytes);
    return bytes;
  }

  public static byte[] padFile(byte[] byteFile) {
    // 16 bytes to in 128 bits (128/8)
    int extraBytes = byteFile.length % 16 == 0 ? 16 : 16 - byteFile.length % 16;
    byte[] paddedBytes = Arrays.copyOf(byteFile, byteFile.length + extraBytes);
    paddedBytes[byteFile.length] = (byte) Integer.parseInt("10000000", 2);
    return paddedBytes;
  }

  public static byte[] aesEncryptFile(byte[] file, byte[] key, byte[] iVector) {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
      IvParameterSpec ivSpec = new IvParameterSpec(iVector);

      Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
      byte[] paddedFile = padFile(file);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
      return cipher.doFinal(paddedFile);
      // I'm not sure why this code has so many exception types.
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | InvalidAlgorithmParameterException
        | NoSuchPaddingException
        | BadPaddingException
        | IllegalBlockSizeException error) {
      throw new RuntimeException(error);
    }
  }

  public static BigInteger modularExp(BigInteger message, BigInteger pow, BigInteger modulus) {
    // your notes(number theory 1) contained an algorithm that I used as inspiration for this
    // used modPow to test the sanity of the output for this method.
    BigInteger result = BigInteger.valueOf(1);

    for (int i = 0; i < pow.bitLength(); i++) {
      /*
      for i = 0 to n-1 do
        if xi = 1 then y = (y*a) mod p
        a = (a*a) mod p
      end
       */
      if (pow.testBit(i)) {
        result = result.multiply(message).mod(modulus);
      }
      message = message.multiply(message).mod(modulus);
    }
    return result;
  }

  public static byte[] rsaEncrypt(byte[] password, int exponent, String modulus) {
    BigInteger e = BigInteger.valueOf(exponent);
    BigInteger m = new BigInteger(modulus, 16);
    BigInteger p = new BigInteger(password);
    return modularExp(p, e, m).toByteArray();
  }
}
