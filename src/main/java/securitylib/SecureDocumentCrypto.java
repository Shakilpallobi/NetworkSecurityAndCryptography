package securitylib;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;

/**
 * Core class for performing Protect/Check/Unprotect cryptographic operations.
 * Implements Hybrid Encryption (AES + RSA/OAEP) for SR1 and Digital Signatures (SHA256withRSA) for SR3.
 */
public class SecureDocumentCrypto {

    // Asymmetric Algorithm for Key Encapsulation (SR1) and Digital Signatures (SR3)
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_ENCRYPTION_MODE = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"; 

    // Symmetric Algorithm for Bulk Data Encryption (SR1) - AES GCM is modern and authenticated
    private static final String AES_ALGORITHM = "AES";
    private static final String AES_ENCRYPTION_MODE = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag
    private static final int GCM_IV_LENGTH = 12;   // 12-byte IV/Nonce

    // Signature Algorithm for Integrity (SR3)
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    // --- Digital Signature Methods (SR3: Integrity) ---

    /**
     * Signs the input data using the given Private Key.
     * @param data The data (JSON string bytes) to be signed.
     * @param privateKey The Private Key of the signatory (Seller or Buyer).
     * @return The digital signature as a byte array.
     * @throws GeneralSecurityException if signing fails.
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey, new SecureRandom());
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies a digital signature against the original data and a Public Key.
     * @param data The original data (JSON string bytes).
     * @param signatureBytes The signature byte array.
     * @param publicKey The Public Key of the expected signatory.
     * @return True if the signature is valid, false otherwise.
     * @throws GeneralSecurityException if verification fails.
     */
    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    // --- Hybrid Encryption Methods (SR1: Confidentiality) ---

    /**
     * Encrypts the bulk data using a symmetric AES key (part of the hybrid scheme).
     * Includes a randomly generated IV/Nonce in the output to be safe for GCM mode.
     * @param data The data (JSON string bytes) to encrypt.
     * @param key The AES Secret Key.
     * @return Encrypted data combined with the IV/Nonce.
     * @throws GeneralSecurityException if encryption fails.
     */
    public static byte[] encryptAES(byte[] data, SecretKey key) throws GeneralSecurityException {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

        Cipher cipher = Cipher.getInstance(AES_ENCRYPTION_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] ciphertext = cipher.doFinal(data);

        // Concatenate IV and Ciphertext for transport/storage
        byte[] output = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(ciphertext, 0, output, iv.length, ciphertext.length);
        return output;
    }

    /**
     * Decrypts the bulk data using a symmetric AES key.
     * Extracts the IV/Nonce from the beginning of the ciphertext.
     * @param dataWithIv The encrypted data with the IV/Nonce prepended.
     * @param key The AES Secret Key.
     * @return The decrypted plaintext data.
     * @throws GeneralSecurityException if decryption fails.
     */
    public static byte[] decryptAES(byte[] dataWithIv, SecretKey key) throws GeneralSecurityException {
        if (dataWithIv.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Ciphertext is too short; missing IV.");
        }
        
        // Extract IV and Ciphertext
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(dataWithIv, 0, iv, 0, GCM_IV_LENGTH);
        byte[] ciphertext = new byte[dataWithIv.length - GCM_IV_LENGTH];
        System.arraycopy(dataWithIv, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        
        Cipher cipher = Cipher.getInstance(AES_ENCRYPTION_MODE);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(ciphertext);
    }

    /**
     * Encrypts the symmetric AES key using a recipient's RSA Public Key (Key Wrap).
     * @param symmetricKey The AES Secret Key to encrypt.
     * @param publicKey The recipient's RSA Public Key.
     * @return The encrypted AES key bytes.
     * @throws GeneralSecurityException if encryption fails.
     */
    public static byte[] encryptKeyRSA(SecretKey symmetricKey, PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ENCRYPTION_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(symmetricKey.getEncoded());
    }

    /**
     * Decrypts the symmetric AES key using the recipient's RSA Private Key (Key Unwrap).
     * @param encryptedKey The encrypted AES key bytes.
     * @param privateKey The recipient's RSA Private Key.
     * @return The decrypted AES SecretKey object.
     * @throws GeneralSecurityException if decryption or key reconstruction fails.
     */
    public static SecretKey decryptKeyRSA(byte[] encryptedKey, PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(RSA_ENCRYPTION_MODE);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedKeyBytes = cipher.doFinal(encryptedKey);
        return new SecretKeySpec(decryptedKeyBytes, AES_ALGORITHM);
    }

    // --- Disclosure Record Implementation (SR4: Integrity 2) ---

    /**
     * Creates a signed record of the sharing event (for SR4).
     * This record is used to verify with whom the transaction was shared.
     * @param transactionId The ID of the transaction being shared.
     * @param sharerId The ID of the party performing the sharing (e.g., "Buyer").
     * @param recipientId The ID of the new recipient (e.g., "Company C").
     * @param sharerKey Private key of the sharer to sign the record.
     * @return A JSON object containing the signed disclosure record.
     * @throws Exception if signing fails.
     */
    public static JSONObject createSignedDisclosureRecord(int transactionId, String sharerId, String recipientId, PrivateKey sharerKey) throws Exception {
        JSONObject record = new JSONObject();
        record.put("transactionId", transactionId);
        record.put("sharerId", sharerId);
        record.put("recipientId", recipientId);
        record.put("timestamp", System.currentTimeMillis() / 1000L);

        // Sign the data part of the record
        byte[] recordBytes = record.toString().getBytes("UTF-8");
        byte[] signature = sign(recordBytes, sharerKey);

        JSONObject signedRecord = new JSONObject();
        signedRecord.put("record", record);
        signedRecord.put("signature", Base64.getEncoder().encodeToString(signature));
        
        System.out.printf("Disclosure Record created: %s shared Transaction %d with %s\n", sharerId, transactionId, recipientId);
        return signedRecord;
    }
}