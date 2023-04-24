import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.security.*;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class PasswordHashing {

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
//
//        System.out.println("Encrypted Message: " + Base64.getEncoder().encodeToString(encryptedMessage));
//        System.out.println("\nUsed Public key: " + keyPair.getPublic());
//
//        // Decrypt the message using the private key from the generated key pair
//        String decryptedMessage = async_dec(encryptedMessage, keyPair.getPrivate());
//        System.out.println("\nDecrypted Message: " + decryptedMessage);
//        System.out.println("Used Private key: " + keyPair.getPrivate());

        // Step-4 ZKP
        zkp(password);
    }

    //step-4
    public static void zkp(String storedPassword){
        try (Scanner scanner = new Scanner(System.in)) {

            // Generate a key pair for the user
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            SecureRandom random = new SecureRandom();
            keyGen.initialize(256, random);
            KeyPair keyPair = keyGen.generateKeyPair();

            // Take input from the user to verify password
            System.out.print("verify your password: ");
            String password = scanner.nextLine();

            // Compare the user input to the stored password
            boolean passwordMatch = storedPassword.equals(password);

            // Generate a challenge for the user to prove knowledge of the password
            byte[] challenge = new byte[32];
            random.nextBytes(challenge);

            // Sign the challenge using the user's private key and password match
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(challenge);
            signature.update((byte) (passwordMatch ? 1 : 0));
            byte[] proof = signature.sign();

            // Verify the proof using the user's public key, challenge, and password match
            signature.initVerify(keyPair.getPublic());
            signature.update(challenge);
            signature.update((byte) (passwordMatch ? 1 : 0));
            boolean verified = signature.verify(proof);

            if (verified) {
                if (passwordMatch) {
                    System.out.println("Proof verified - password accepted!");
                } else {
                    System.out.println("Proof verified - password rejected!");
                }
            } else {
                System.out.println("Proof not verified - password rejected!");
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
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
