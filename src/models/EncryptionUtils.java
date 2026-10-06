package models;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Cryptographic helpers used by the vault and file encryptor.
 *
 * <p>New password-encrypted data is self-describing: it contains a magic
 * value, format version and random PBKDF2 salt before the AES-GCM payload.
 * The old IV+ciphertext format is still accepted when reading so existing
 * vaults and files can be migrated without data loss.</p>
 */
public final class EncryptionUtils {

    private static final String LEGACY_HASH_ALGORITHM = "SHA-256";
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    private static final int AES_KEY_LENGTH = 256;
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int SALT_LENGTH = 16;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;
    private static final byte[] FORMAT_MAGIC = {'S', 'S', 'V', '2'};
    private static final int FORMAT_VERSION = 1;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static final int MINIMUM_PASSWORD_LENGTH = 8;
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:',.<>?/~`";

    public static final String PASSWORD_REQUIREMENTS =
            "Requisitos de la contraseña:\n" +
                    "  • Mínimo 8 caracteres\n" +
                    "  • Al menos una letra mayúscula\n" +
                    "  • Al menos un número\n" +
                    "  • Al menos un carácter especial (!@#$%^&* etc.)";

    private EncryptionUtils() {
    }

    public static String validatePasswordPolicy(String password) {
        if (password == null || password.length() < MINIMUM_PASSWORD_LENGTH) {
            return "La contraseña debe tener al menos " + MINIMUM_PASSWORD_LENGTH + " caracteres.";
        }
        boolean hasUppercase = false;
        boolean hasNumber = false;
        boolean hasSpecial = false;
        for (char c : password.toCharArray()) {
            hasUppercase |= Character.isUpperCase(c);
            hasNumber |= Character.isDigit(c);
            hasSpecial |= SPECIAL_CHARACTERS.indexOf(c) >= 0;
        }
        if (!hasUppercase) {
            return "La contraseña debe contener al menos una letra mayúscula.";
        }
        if (!hasNumber) {
            return "La contraseña debe contener al menos un número.";
        }
        if (!hasSpecial) {
            return "La contraseña debe contener al menos un carácter especial (!@#$%^&* etc.).";
        }
        return null;
    }

    /**
     * Retained for source compatibility with older callers. New persisted
     * data must use {@link #encryptWithPassword(byte[], String)}.
     */
    @Deprecated
    public static SecretKey deriveKeyFromPassword(String password) throws Exception {
        return deriveLegacyKey(password);
    }

    private static SecretKey deriveLegacyKey(String password) throws Exception {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("La contraseña no puede estar vacía.");
        }
        byte[] keyBytes = MessageDigest.getInstance(LEGACY_HASH_ALGORITHM)
                .digest(password.getBytes(StandardCharsets.UTF_8));
        return new SecretKeySpec(keyBytes, "AES");
    }

    /** Derives an AES-256 key using a per-file random salt. */
    public static SecretKey deriveKeyFromPassword(String password, byte[] salt) throws Exception {
        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("La contraseña no puede estar vacía.");
        }
        if (salt == null || salt.length < 8) {
            throw new IllegalArgumentException("La sal criptográfica no es válida.");
        }
        char[] passwordChars = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt,
                PBKDF2_ITERATIONS, AES_KEY_LENGTH);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } finally {
            spec.clearPassword();
            Arrays.fill(passwordChars, '\0');
        }
    }

    /**
     * Encrypts with PBKDF2 and AES-GCM. The result includes all parameters
     * required for decryption and is safe to store as-is.
     */
    public static byte[] encryptWithPassword(byte[] data, String password) throws Exception {
        if (data == null) {
            throw new IllegalArgumentException("Los datos no pueden ser nulos.");
        }
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        byte[] header = createHeader(salt);
        byte[] payload = encrypt(data, deriveKeyFromPassword(password, salt), header);
        return ByteBuffer.allocate(header.length + payload.length).put(header).put(payload).array();
    }

    /**
     * Decrypts either the current versioned format or the legacy SHA-256
     * format. Callers can inspect {@link DecryptionResult#legacy()} to migrate.
     */
    public static DecryptionResult decryptWithPassword(byte[] encryptedData, String password) throws Exception {
        if (encryptedData == null || encryptedData.length == 0) {
            throw new IllegalArgumentException("Los datos cifrados están vacíos.");
        }
        if (startsWithMagic(encryptedData)) {
            int headerLength = FORMAT_MAGIC.length + 1 + SALT_LENGTH;
            if (encryptedData.length < FORMAT_MAGIC.length + 1) {
                throw new IllegalArgumentException("Los datos cifrados están incompletos.");
            }
            int version = encryptedData[FORMAT_MAGIC.length] & 0xff;
            if (version != FORMAT_VERSION) {
                throw new IllegalArgumentException("Versión de cifrado no compatible: " + version);
            }
            if (encryptedData.length < headerLength + GCM_IV_LENGTH + (GCM_TAG_LENGTH / 8)) {
                throw new IllegalArgumentException("Los datos cifrados están incompletos.");
            }
            byte[] header = Arrays.copyOfRange(encryptedData, 0, headerLength);
            byte[] salt = Arrays.copyOfRange(encryptedData, FORMAT_MAGIC.length + 1, headerLength);
            byte[] payload = Arrays.copyOfRange(encryptedData, headerLength, encryptedData.length);
            return new DecryptionResult(decrypt(payload, deriveKeyFromPassword(password, salt), header), false);
        }
        // Legacy vaults/files were IV + AES-GCM(ciphertext), keyed by SHA-256.
        return new DecryptionResult(decrypt(encryptedData, deriveLegacyKey(password)), true);
    }

    private static byte[] createHeader(byte[] salt) {
        return ByteBuffer.allocate(FORMAT_MAGIC.length + 1 + salt.length)
                .put(FORMAT_MAGIC)
                .put((byte) FORMAT_VERSION)
                .put(salt)
                .array();
    }

    private static boolean startsWithMagic(byte[] data) {
        if (data.length < FORMAT_MAGIC.length) {
            return false;
        }
        return Arrays.equals(FORMAT_MAGIC, Arrays.copyOf(data, FORMAT_MAGIC.length));
    }

    /** Encrypts with AES-GCM and prepends a fresh 96-bit IV. */
    public static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        return encrypt(data, key, null);
    }

    private static byte[] encrypt(byte[] data, SecretKey key, byte[] aad) throws Exception {
        if (data == null || key == null) {
            throw new IllegalArgumentException("Los datos y la clave son obligatorios.");
        }
        byte[] iv = new byte[GCM_IV_LENGTH];
        RANDOM.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        byte[] encryptedData = cipher.doFinal(data);
        return ByteBuffer.allocate(iv.length + encryptedData.length).put(iv).put(encryptedData).array();
    }

    /** Decrypts an IV + AES-GCM payload after validating its minimum length. */
    public static byte[] decrypt(byte[] encryptedData, SecretKey key) throws Exception {
        return decrypt(encryptedData, key, null);
    }

    private static byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] aad) throws Exception {
        int minimumLength = GCM_IV_LENGTH + (GCM_TAG_LENGTH / 8);
        if (encryptedData == null || encryptedData.length < minimumLength) {
            throw new IllegalArgumentException("Los datos cifrados están incompletos.");
        }
        if (key == null) {
            throw new IllegalArgumentException("La clave no puede ser nula.");
        }
        byte[] iv = Arrays.copyOfRange(encryptedData, 0, GCM_IV_LENGTH);
        byte[] actualData = Arrays.copyOfRange(encryptedData, GCM_IV_LENGTH, encryptedData.length);
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
        if (aad != null) {
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(actualData);
    }

    public static final class DecryptionResult {
        private final byte[] data;
        private final boolean legacy;

        private DecryptionResult(byte[] data, boolean legacy) {
            this.data = data;
            this.legacy = legacy;
        }

        public byte[] data() {
            return data;
        }

        public boolean legacy() {
            return legacy;
        }
    }
}
