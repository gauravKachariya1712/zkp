import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.security.*;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
//import org.bouncycastle.*;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.SCrypt;
import java.security.spec.KeySpec;

public class PasswordHashing {
    private static final int SCRYPT_N = 16384;
    private static final int SCRYPT_R = 8;
    private static final int SCRYPT_P = 1;
    private static final int SALT_LENGTH = 16;

    public static void main(String[] args) throws Exception {
        Console console = System.console();
        Scanner input = new Scanner(System.in);
        System.out.print("Enter your password: ");
        String password = input.nextLine();

        //Step-1
//        hashPassword(password);

        //step-2
//        aes_enc(password);
//        System.out.print("Enter a hashed value to decrypt: ");
//        String hashedValue = input.nextLine();
//        System.out.print("Enter the key: ");
//        String keyString = input.nextLine();
//        aes_dec(hashedValue, keyString);

        //step-3
//        KeyPair keyPair = generateRSAKeyPair();
//        // Encrypt the message using the public key from the generated key pair
//        byte[] encryptedMessage = async_enc(password, keyPair.getPublic());
//        System.out.println("Encrypted Message: " + new String(encryptedMessage));
//        System.out.println("\nUsed Public key: " + keyPair.getPublic());
//
//        // Decrypt the message using the private key from the generated key pair
//        String decryptedMessage = async_dec(encryptedMessage, keyPair.getPrivate());
//
//        System.out.println("\nDecrypted Message: " + decryptedMessage);
//        System.out.println("Used Private key: " + keyPair.getPrivate());

        // Step-4
        byte[] salt = generateSalt();
        byte[] encryptedPass = hash(scrypt(password.getBytes(), salt, 32));
        byte[] challenge = generateSalt();
        byte[] response = scrypt(password.getBytes(), challenge, 32);
        boolean verified = verifyPassword(response, challenge, encryptedPass);

        if (verified) {
            System.out.println("Password verified");
        } else {
            System.out.println("Incorrect password");
        }
    }

    //step-4
    public static byte[] hash(byte[] message) {
        SHA256Digest digest = new SHA256Digest();
        byte[] output = new byte[digest.getDigestSize()];
        digest.update(message, 0, message.length);
        digest.doFinal(output, 0);
        return output;
    }

    private static byte[] scrypt(byte[] password, byte[] salt, int dkLen) {
        return SCrypt.generate(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, dkLen);
    }

    private static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        return salt;
    }

    private static boolean verifyPassword(byte[] password, byte[] salt, byte[] verification) {
        byte[] expectedVerification = hash(scrypt(password, salt, 32));
        return MessageDigest.isEqual(expectedVerification, verification);
    }


    //step-3
    public static byte[] async_enc(String plainText, java.security.PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
    }
    public static String async_dec(byte[] cipherText, java.security.PrivateKey privateKey) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(cipherText));
    }
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        // Create a KeyPairGenerator object for RSA encryption
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

        // Initialize the generator with a key size of 2048 bits
        keyPairGen.initialize(2048);

        // Generate a new RSA key pair
        return keyPairGen.generateKeyPair();
    }

    //Step-2
    public static void aes_enc(String passwd) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        //Generate a random key
        byte[] keyBytes = new byte[16];
        new Random().nextBytes(keyBytes);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        // Encrypt the string using the key
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] generatedPassword = cipher.doFinal(passwd.getBytes());
        String encodedPassword = Base64.getEncoder().encodeToString(generatedPassword);
        System.out.println("Encrypted password: " + encodedPassword);
        System.out.println("Key used: " + Base64.getEncoder().encodeToString(keyBytes));
    }

    public static void aes_dec(String hashedValue, String keyString) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Decrypt the hashed value using the key
        byte[] keyBytesFromUser = Base64.getDecoder().decode(keyString);
        SecretKey secretKeyFromUser = new SecretKeySpec(keyBytesFromUser, "AES");

        Cipher cipherFromUser = Cipher.getInstance("AES");
        cipherFromUser.init(Cipher.DECRYPT_MODE, secretKeyFromUser);
        byte[] decryptedBytes = cipherFromUser.doFinal(Base64.getDecoder().decode(hashedValue));
        String decryptedString = new String(decryptedBytes);

        System.out.println("Password Decrypted: " + decryptedString);
    }

    //Step 1
    public static void hashPassword(String password) {
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
            System.out.println("Encrypted Password: " + generatedPassword);
    }


}