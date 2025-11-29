package securitylib;

import org.json.JSONObject;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.SecretKey;
import java.security.MessageDigest; 
import java.security.KeyPair;      
import java.security.Key;          
import java.security.KeyFactory; 
import java.security.spec.X509EncodedKeySpec; 

/**
 * Main application class providing the command-line interface (CLI) for the
 * Secure Document Library.
 */
public class MainApp {

    private static final String DEFAULT_CHARSET = "UTF-8";

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equals("help")) {
            printHelp();
            return;
        }

        try {
            String command = args[0].toLowerCase();
            switch (command) {
                case "help":
                    printHelp();
                    break;
                case "genkeys":
                    KeyManager.generateDummyKeys(new String[]{"Seller", "Buyer", "ThirdParty"});
                    break;
                case "protect":
                    // protect (input-file) (seller-priv-key) (buyer-pub-key) (output-file)
                    // We must pass the Buyer's private key for signing, so we will require 5 arguments for now.
                    if (args.length < 5) throw new IllegalArgumentException("Missing arguments for 'protect'.");
                    protect(args[1], args[2], args[3], args[4]);
                    break;
                case "check":
                    // check (input-file) (seller-pub-key) (buyer-pub-key)
                    if (args.length < 4) throw new IllegalArgumentException("Missing arguments for 'check'.");
                    check(args[1], args[2], args[3]);
                    break;
                case "unprotect":
                    // unprotect (input-file) (recipient-priv-key) (output-file)
                    if (args.length < 4) throw new IllegalArgumentException("Missing arguments for 'unprotect'.");
                    unprotect(args[1], args[2], args[3]);
                    break;
                default:
                    System.err.println("Error: Unknown command '" + command + "'");
                    printHelp();
            }
        } catch (Exception e) {
            System.err.println("\n--- ERROR SUMMARY ---");
            System.err.println("Command failed: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private static void printHelp() {
        System.out.println("--- Secure Document Library CLI ---");
        System.out.println("Commands:");
        System.out.println("  help                                 - Print this help message.");
        System.out.println("  genkeys                              - Generate dummy seller/buyer key files.");
        System.out.println("  protect <input> <seller_priv> <buyer_pub> <output>");
        System.out.println("                                       - Encrypts and signs the document (SR1, SR3).");
        System.out.println("                                         <seller_priv> is used for signing and <buyer_pub> for key wrapping.");
        System.out.println("  check <input> <seller_pub> <buyer_pub>");
        System.out.println("                                       - Verifies integrity of signatures (SR3).");
        System.out.println("  unprotect <input> <recipient_priv> <output>");
        System.out.println("                                       - Decrypts the document using the recipient's private key (SR1).");
    }

    /**
     * Implements the protect() operation: Encrypts the document and adds two signatures.
     * Arguments: inputFile, sellerPrivKeyFile, buyerPubKeyFile, outputFile
     */
    private static void protect(String inputFile, String sellerPrivKeyFile, String buyerPubKeyFile, String outputFile) throws Exception {
        System.out.println("\n--- PROTECTING DOCUMENT ---");
        
        // 1. Read input document
        byte[] originalDataBytes = Files.readAllBytes(Paths.get(inputFile));
        String originalData = new String(originalDataBytes, DEFAULT_CHARSET);

        // 2. Generate Session Key (K_sess)
        SecretKey sessionKey = KeyManager.generateAESKey();
        
        // 3. Encrypt the bulk data (SR1)
        byte[] encryptedDataWithIv = SecureDocumentCrypto.encryptAES(originalDataBytes, sessionKey);
        
        // 4. Load RSA Keys
        PrivateKey sellerPrivKey = KeyManager.loadPrivateKey(sellerPrivKeyFile);
        PublicKey buyerPubKey = KeyManager.loadPublicKey(buyerPubKeyFile);
        
        // *** FIX: Load the Buyer's PRIVATE key for signing (SR3) ***
        // NOTE: The signature must be performed by the Buyer's private key. 
        // We load the known private key file, assuming it's available in the working directory.
        PrivateKey buyerPrivKey = KeyManager.loadPrivateKey("buyer_private.key"); 
        
        // --- Seller's Public Key for Key Wrapping (SR1) ---
        // NOTE: This assumes the seller's public key file exists alongside the private key file argument: seller_private.key -> seller_public.key
        String sellerPubKeyFile = sellerPrivKeyFile.replace("_private.key", "_public.key");
        PublicKey sellerPubKey = KeyManager.loadPublicKey(sellerPubKeyFile);
        
        // 5. Encrypt K_sess for participants (Key Wrap, SR1)
        byte[] encryptedKeyForSeller = SecureDocumentCrypto.encryptKeyRSA(sessionKey, sellerPubKey); // Seller can now decrypt it later
        byte[] encryptedKeyForBuyer = SecureDocumentCrypto.encryptKeyRSA(sessionKey, buyerPubKey);
        
        // 6. Digital Signatures (SR3)
        byte[] sellerSignature = SecureDocumentCrypto.sign(originalDataBytes, sellerPrivKey);
        // FIX: Sign using the loaded Buyer Private Key
        byte[] buyerSignature = SecureDocumentCrypto.sign(originalDataBytes, buyerPrivKey); 

        // 7. Assemble the final protected document (JSON format)
        JSONObject protectedDoc = new JSONObject();
        protectedDoc.put("originalHash", Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(originalDataBytes))); // Optional debug/quick check
        protectedDoc.put("encryptedData", Base64.getEncoder().encodeToString(encryptedDataWithIv));
        
        // Encrypted keys map
        JSONObject encryptedKeys = new JSONObject();
        encryptedKeys.put("seller", Base64.getEncoder().encodeToString(encryptedKeyForSeller));
        encryptedKeys.put("buyer", Base64.getEncoder().encodeToString(encryptedKeyForBuyer));
        protectedDoc.put("encryptedKeys", encryptedKeys);

        // Signatures map
        JSONObject signatures = new JSONObject();
        signatures.put("sellerSignature", Base64.getEncoder().encodeToString(sellerSignature));
        signatures.put("buyerSignature", Base64.getEncoder().encodeToString(buyerSignature));
        protectedDoc.put("signatures", signatures);

        // 8. Write protected document to file
        Files.write(Paths.get(outputFile), protectedDoc.toString(4).getBytes(DEFAULT_CHARSET));
        
        System.out.println("Document successfully PROTECTED.");
        System.out.println("Output file: " + outputFile);
    }

    /**
     * Implements the check() operation: Verifies the integrity of the protected document's signatures.
     * Arguments: inputFile, sellerPubKeyFile, buyerPubKeyFile
     */
    private static void check(String inputFile, String sellerPubKeyFile, String buyerPubKeyFile) throws Exception {
        System.out.println("\n--- CHECKING DOCUMENT INTEGRITY (SR3) ---");
        
        // 1. Read protected document
        String protectedDocJson = new String(Files.readAllBytes(Paths.get(inputFile)), DEFAULT_CHARSET);
        JSONObject protectedDoc = new JSONObject(protectedDocJson);
        
        // 2. Load necessary keys (Public keys for verification)
        PublicKey sellerPubKey = KeyManager.loadPublicKey(sellerPubKeyFile);
        PublicKey buyerPubKey = KeyManager.loadPublicKey(buyerPubKeyFile);

        // 3. Extract necessary components
        byte[] encryptedDataWithIv = Base64.getDecoder().decode(protectedDoc.getString("encryptedData"));
        JSONObject signatures = protectedDoc.getJSONObject("signatures");
        
        byte[] sellerSignature = Base64.getDecoder().decode(signatures.getString("sellerSignature"));
        byte[] buyerSignature = Base64.getDecoder().decode(signatures.getString("buyerSignature"));
        
        // 4. A successful check requires the data to be decrypted first to get the original data for verification.
        
        // --- STEP 4a: Load Dummy Private Key (Only for this demonstration check) ---
        // For this check, we use the seller's private key to decrypt and get the original data.
        String dummySellerPrivKeyFile = "seller_private.key"; 
        if (!new File(dummySellerPrivKeyFile).exists()) {
             System.err.println("Error: 'check' requires access to a private key to decrypt data for integrity verification. Run 'genkeys' first.");
             return;
        }
        PrivateKey dummySellerPrivKey = KeyManager.loadPrivateKey(dummySellerPrivKeyFile);
        
        // --- STEP 4b: Decrypt Session Key ---
        byte[] encryptedKeyForSeller = Base64.getDecoder().decode(protectedDoc.getJSONObject("encryptedKeys").getString("seller"));
        SecretKey sessionKey = SecureDocumentCrypto.decryptKeyRSA(encryptedKeyForSeller, dummySellerPrivKey);
        
        // --- STEP 4c: Decrypt Data to get Original Plaintext ---
        byte[] originalDataBytes = SecureDocumentCrypto.decryptAES(encryptedDataWithIv, sessionKey);

        // 5. Verification (SR3)
        boolean sellerValid = SecureDocumentCrypto.verify(originalDataBytes, sellerSignature, sellerPubKey);
        boolean buyerValid = SecureDocumentCrypto.verify(originalDataBytes, buyerSignature, buyerPubKey);
        
        System.out.println("Original Data Content (Decrypted for Verification): \n" + new String(originalDataBytes, DEFAULT_CHARSET));
        System.out.println("\nVerification Results:");
        System.out.println("  Seller Signature Valid: " + (sellerValid ? "✅ YES" : "❌ NO"));
        System.out.println("  Buyer Signature Valid:  " + (buyerValid ? "✅ YES" : "❌ NO"));
        
        if (sellerValid && buyerValid) {
            System.out.println("\nDocument integrity is successfully verified (SR3).");
        } else {
            System.out.println("\nDocument integrity verification FAILED.");
        }
    }

    /**
     * Implements the unprotect() operation: Decrypts the document.
     * Arguments: inputFile, recipientPrivKeyFile, outputFile
     */
    private static void unprotect(String inputFile, String recipientPrivKeyFile, String outputFile) throws Exception {
        System.out.println("\n--- UNPROTECTING DOCUMENT (SR1) ---");

        // 1. Read protected document
        String protectedDocJson = new String(Files.readAllBytes(Paths.get(inputFile)), DEFAULT_CHARSET);
        JSONObject protectedDoc = new JSONObject(protectedDocJson);
        
        // 2. Load Recipient's Private Key
        PrivateKey recipientPrivKey = KeyManager.loadPrivateKey(recipientPrivKeyFile);

        // 3. Find the encrypted key for this recipient based on the key file name (e.g., 'buyer_private.key' -> 'buyer')
        String recipientId = new File(recipientPrivKeyFile).getName().split("_")[0];
        
        if (!protectedDoc.getJSONObject("encryptedKeys").has(recipientId)) {
            throw new Exception("Error: Document not intended for recipient '" + recipientId + "' or key file name is incorrect.");
        }

        // 4. Decrypt Session Key (Key Unwrap, SR1)
        byte[] encryptedKey = Base64.getDecoder().decode(protectedDoc.getJSONObject("encryptedKeys").getString(recipientId));
        SecretKey sessionKey = SecureDocumentCrypto.decryptKeyRSA(encryptedKey, recipientPrivKey);
        
        System.out.println("Session key successfully decrypted using " + recipientId + "'s private key.");

        // 5. Decrypt Bulk Data (SR1)
        byte[] encryptedDataWithIv = Base64.getDecoder().decode(protectedDoc.getString("encryptedData"));
        byte[] originalDataBytes = SecureDocumentCrypto.decryptAES(encryptedDataWithIv, sessionKey);
        String decryptedData = new String(originalDataBytes, DEFAULT_CHARSET);

        // 6. Write to output file
        Files.write(Paths.get(outputFile), decryptedData.getBytes(DEFAULT_CHARSET));
        
        System.out.println("Document successfully UNPROTECTED (Confidentiality Achieved).");
        System.out.println("Output file: " + outputFile);
    }
}