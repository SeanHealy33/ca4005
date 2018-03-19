/*
Student: Sean Healy CPSSD4
Number: 13411482

I declare that this material, which I now submit for assessment, is entirely my
own work and has not been taken from the work of others, save and to the extent that such
work has been acknowledged within the text of my work.
*/

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class elGamal {
  public static void main(String[] args) {
    String primeMod = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
    String generator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";

    BigInteger primeBigInt = new BigInteger(primeMod, 16);
    BigInteger genBigInt = new BigInteger(generator, 16);

    // create public and private keys
    BigInteger secretKey = createRandomBInt(primeBigInt);
    BigInteger publicKey = modPow(primeBigInt, genBigInt, secretKey);

    BigInteger fileBI = new BigInteger(sha256(readFile(args[0])));

    BigInteger[] krs = createValidKRS(primeBigInt, genBigInt, secretKey, fileBI);

    System.out.println("KRS\n");

    System.out.println("k= " + krs[0].toString(16));
    System.out.println("r = " + krs[1].toString(16));
    System.out.println("s = " + krs[2].toString(16));

    System.out.println("public/private key\n");

    System.out.println("Public Key = " + publicKey.toString(16));
    System.out.println("Secret Key = " + secretKey.toString(16));
  }

  public static BigInteger[] createValidKRS(
      BigInteger primeBigInt, BigInteger genBigInt, BigInteger secretKey, BigInteger fileBI) {

    BigInteger primeDec = primeBigInt.subtract(BigInteger.valueOf(1));
    BigInteger k = createRandomK(primeDec);
    BigInteger r = modPow(primeBigInt, genBigInt, k);
    BigInteger s = createS(fileBI, secretKey, primeDec, r, k);
    if (s == BigInteger.valueOf(0)) {
      return createValidKRS(primeBigInt, genBigInt, secretKey, fileBI);
    }
    return new BigInteger[] {k, r, s};
  }

  public static BigInteger createRandomBInt(BigInteger prime) {
    SecureRandom random = new SecureRandom();
    // the 1 increases the chances that this number is prime.
    return new BigInteger(prime.bitLength(), 1, random);
  }

  public static BigInteger createRandomK(BigInteger primeDec) {
    BigInteger randK = createRandomBInt(primeDec);
    if (getGCD(randK, primeDec).equals(BigInteger.valueOf(1)) && randK.compareTo(primeDec) == 1) {
      return createRandomK(primeDec);
    }
    return randK;
  }

  public static BigInteger createS(
      BigInteger file, BigInteger secretKey, BigInteger primeDec, BigInteger r, BigInteger k) {

    //  (H(m)-xr)k^-1
    BigInteger hashXR = file.subtract(secretKey.multiply(r));
    BigInteger hashXRinverse = hashXR.multiply(multiplicativeInverse(k, primeDec));
    // (mod prime-1)
    return hashXRinverse.mod(primeDec);
  }

  // https://www.tutorialspoint.com/java/math/biginteger_modpow.htm
  public static BigInteger modPow(BigInteger prime, BigInteger generator, BigInteger pow) {
    // g^k mod(p) && g^x (mod p)
    return generator.modPow(pow, prime);
  }

  //  http://www.algorithmist.com/index.php/Modular_inverse
  //  this proved very handy in helping me. I tested my output against the bigint method
  //  modInverse
  public static BigInteger multiplicativeInverse(BigInteger a, BigInteger b) {
    BigInteger[] extResp = extEuclid(a, b);
    if (!extResp[0].equals(BigInteger.valueOf(1))) {
      throw new RuntimeException("No Inverse possible between numbers");
    } else {
      return extResp[1].mod(b);
    }
  }

  public static BigInteger[] extEuclid(BigInteger a, BigInteger b) {
    if (b == BigInteger.valueOf(0)) {
      return new BigInteger[] {a, BigInteger.valueOf(1), BigInteger.valueOf(0)};
    } else {
      BigInteger[] arr = extEuclid(b, a.mod(b));
      // g, x, y
      BigInteger newy = arr[1].subtract((a.divide(b)).multiply(arr[2]));
      // g, y, newy
      return new BigInteger[] {arr[0], arr[2], newy};
    }
  }

  // https://www.khanacademy.org/computing/computer-science/cryptography/modarithmetic/a/the-euclidean-algorithm
  // used this for building my GCD algorithm
  public static BigInteger getGCD(BigInteger a, BigInteger b) {
    if (b == BigInteger.valueOf(0)) {
      return a;
    }
    return getGCD(b, a.mod(b));
  }

  public static byte[] readFile(String fileName) {
    try {
      return Files.readAllBytes(new File("./" + fileName).toPath());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  // Mostly copy pasted this from my assessment 1
  public static byte[] sha256(byte[] hashMessage) {
    try {
      MessageDigest shaHash = MessageDigest.getInstance("SHA-256");
      return shaHash.digest(hashMessage);
    } catch (Exception error) {
      throw new RuntimeException(error);
    }
  }
}
