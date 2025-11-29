package securitylib;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec; // Added import
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

/**
 * Utility class for generating, saving, and loading cryptographic keys.
 * Uses default Java Cryptography Architecture (JCA/JCE).
 */
public class KeyManager {

    private static final String RSA_ALGORITHM = "RSA";
    private static final int RSA_KEY_SIZE = 3072; // Modern standard is 2048+, 3072 is robust.
    private static final int AES_KEY_SIZE = 256; // Required for strong confidentiality (SR1).

    // --- Key Generation ---

    /**
     * Generates a strong RSA KeyPair (Public and Private Key).
     * @return A KeyPair object containing the generated public and private keys.
     * @throws NoSuchAlgorithmException if the RSA algorithm is not supported.
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        System.out.printf("Generating %d-bit RSA KeyPair...\n", RSA_KEY_SIZE);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        // Using a secure source of randomness is crucial
        keyPairGenerator.initialize(RSA_KEY_SIZE, new SecureRandom()); 
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Generates a strong AES SecretKey.
     * @return A SecretKey object.
     * @throws NoSuchAlgorithmException if the AES algorithm is not supported.
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }

    // --- Key Storage/Loading ---

    /**
     * Saves a key (Public or Private) to a file in Base64 encoded format.
     * Public Keys use X.509 format; Private Keys use PKCS#8 format.
     * @param key The Key object to save.
     * @param filename The path to the file.
     * @throws IOException if file saving fails.
     */
    public static void saveKey(Key key, String filename) throws IOException {
        byte[] encodedKey = key.getEncoded();
        String base64Key = Base64.getEncoder().encodeToString(encodedKey);
        
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            // Write key type and encoding as simple headers for readability/debugging
            String header = String.format("# %s Key: %s\n", 
                                        key instanceof PrivateKey ? "PRIVATE" : "PUBLIC", 
                                        key.getFormat());
            fos.write(header.getBytes());
            fos.write(base64Key.getBytes());
            System.out.println("Key saved to: " + filename);
        }
    }
    
    /**
     * Loads a Private Key from a Base64-encoded file.
     * @param filename Path to the private key file.
     * @return The loaded PrivateKey object.
     * @throws Exception if loading or key conversion fails.
     */
    public static PrivateKey loadPrivateKey(String filename) throws Exception {
        String base64Key = readKeyFile(filename);
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * Loads a Public Key from a Base64-encoded file.
     * @param filename Path to the public key file.
     * @return The loaded PublicKey object.
     * @throws Exception if loading or key conversion fails.
     */
    public static PublicKey loadPublicKey(String filename) throws Exception {
        String base64Key = readKeyFile(filename);
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(keySpec);
    }
    
    /** Helper method to read key content, skipping comment lines. */
    private static String readKeyFile(String filename) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().startsWith("#")) {
                    sb.append(line.trim());
                }
            }
        }
        if (sb.length() == 0) {
            throw new IOException("Key file is empty or invalid: " + filename);
        }
        return sb.toString();
    }

    // --- Dummy Key Generation for CLI testing (Stage 2 requirement) ---

    /**
     * Generates and saves dummy key pairs for a list of users.
     * @param users The list of usernames (e.g., "Seller", "Buyer").
     */
    public static void generateDummyKeys(String[] users) {
        System.out.println("\n--- Generating Dummy Keys ---");
        try {
            for (String user : users) {
                KeyPair pair = generateRSAKeyPair();
                // Save keys to working directory for testing
                saveKey(pair.getPublic(), String.format("%s_public.key", user.toLowerCase()));
                saveKey(pair.getPrivate(), String.format("%s_private.key", user.toLowerCase()));
            }
            System.out.println("\nDummy keys generated successfully. Use these files for protect/check/unprotect commands.");
        } catch (Exception e) {
            System.err.println("Error generating dummy keys: " + e.getMessage());
        }
    }
}