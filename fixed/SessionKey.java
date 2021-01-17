import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

class SessionKey {
  private SecretKey key;

  public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
    KeyGenerator keygen = KeyGenerator.getInstance("AES");
    keygen.init(keylength);
    key = keygen.generateKey();
  }

  public SessionKey(byte[] keybytes) {
    key = new SecretKeySpec(keybytes, "AES");
  }

  public SecretKey getSecretKey() {
    return key;
  }

  public byte[] getKeyBytes() {
    return key.getEncoded();
  }

  // The lower the result, the "more" random the key is (0 < x < 256). Based on
  // the idea that if something
  public int binaryBalanceRandCheck() {
    byte[] k = getKeyBytes();
    int zeroes = 0;
    int ones = 0;
    for (int i = 0; i < k.length; i++) {
      for (int j = 0; j < 8; j++) {
        if (getBitAsBool(k[i], j))
          ones++;
        else
          zeroes++;
      }
    }
    return Math.abs(ones - zeroes);
  }

  private boolean getBitAsBool(byte b, int pos) {
    return ((b >> pos) & 1) > 0;
  }

  public String toStringBits() {
    StringBuilder str = new StringBuilder();
    byte[] k = getKeyBytes();
    for (int i = 0; i < k.length; i++)
      for (int j = 0; j < 8; j++)
        str.append(getBitAsBool(k[i], j) ? 1 : 0);
    return str.toString();
  }

  public String toStringHex() {
    final char[] HEX = "0123456789ABCDEF".toCharArray();
    byte[] k = getKeyBytes();
    char[] hexChars = new char[k.length * 2];
    for (int i = 0; i < k.length; i++) {
      int b = k[i] & 0xFF;
      hexChars[i * 2] = HEX[b >> 4];
      hexChars[i * 2 + 1] = HEX[b & 0x0F];
    }
    return new String(hexChars);
  }

  // public static void main(String[] args) throws NoSuchAlgorithmException {
  // SessionKey k;
  // if (args.length > 0)
  // k = new SessionKey(Integer.parseInt(args[0]));
  // else
  // k = new SessionKey(256);

  // System.out.println(k.toStringBits() + "\n" + k.binaryBalanceRandCheck());
  // }
}
