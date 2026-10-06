import models.EncryptionUtils;
import models.Vault;
import models.VaultStorage;
import modules.FileModule;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;

/**
 * Small dependency-free regression harness. Run with:
 * javac --release 17 -d out src/models/*.java tests/CriticalTests.java
 * java -cp out CriticalTests
 */
public final class CriticalTests {

    private static final String PASSWORD = "ValidPassword9!";

    public static void main(String[] args) throws Exception {
        testVersionedEncryptionAndAad();
        testLegacyCompatibility();
        testVaultRules();
        testStorageMigration();
        testFailedMigrationKeepsLegacy();
        testFileDestinationIsNotOverwritten();
        System.out.println("CriticalTests: OK");
    }

    private static void testVersionedEncryptionAndAad() throws Exception {
        byte[] plain = "datos con espacios  ".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] encrypted = EncryptionUtils.encryptWithPassword(plain, PASSWORD);
        check(java.util.Arrays.equals(plain,
                EncryptionUtils.decryptWithPassword(encrypted, PASSWORD).data()),
                "versioned round trip");

        byte[] tamperedHeader = encrypted.clone();
        tamperedHeader[5] ^= 1;
        expectFailure(() -> EncryptionUtils.decryptWithPassword(tamperedHeader, PASSWORD),
                "AAD must authenticate the salt");

        byte[] unknownVersion = encrypted.clone();
        unknownVersion[4] = 99;
        expectFailure(() -> EncryptionUtils.decryptWithPassword(unknownVersion, PASSWORD),
                "unknown version must be rejected");
    }

    private static void testLegacyCompatibility() throws Exception {
        byte[] plain = "legacy".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256").digest(PASSWORD.getBytes(StandardCharsets.UTF_8)),
                "AES");
        byte[] legacy = EncryptionUtils.encrypt(plain, key);
        EncryptionUtils.DecryptionResult result =
                EncryptionUtils.decryptWithPassword(legacy, PASSWORD);
        check(result.legacy() && java.util.Arrays.equals(plain, result.data()),
                "legacy format compatibility");
        expectFailure(() -> EncryptionUtils.decryptWithPassword(legacy, "WrongPassword9!"),
                "wrong password must fail");
    }

    private static void testVaultRules() throws Exception {
        Vault vault = new Vault();
        vault.addSecret("Email", "  value with spaces  ");
        check(vault.secretExists("email"), "case-insensitive names");
        check("  value with spaces  ".equals(vault.getSecret("EMAIL")),
                "secret value spaces preserved");
        expectFailure(() -> vault.addSecret("eMaIl", "another"),
                "duplicate names must be rejected");
        check(vault.searchSecretsIntelligently("x".repeat(10_000), 100).isEmpty(),
                "search must be bounded");
    }

    private static void testStorageMigration() throws Exception {
        Path work = Path.of("test-work");
        deleteTree(work);
        Files.createDirectories(work);
        Path vaultPath = work.resolve("vault.dat");
        VaultStorage storage = new VaultStorage(vaultPath);
        Vault vault = new Vault();
        vault.addSecret("Name", "value");
        SecretKey legacyKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256").digest(PASSWORD.getBytes(StandardCharsets.UTF_8)),
                "AES");
        byte[] legacy = EncryptionUtils.encrypt(vault.convertToBytes(), legacyKey);
        Files.write(vaultPath, legacy);
        Vault loaded = storage.loadVault(PASSWORD);
        check(loaded.secretExists("name"), "legacy vault loads");
        check(Files.exists(Path.of(vaultPath + ".legacy.bak")), "legacy backup exists");
        check(!EncryptionUtils.decryptWithPassword(Files.readAllBytes(vaultPath), PASSWORD).legacy(),
                "migration publishes current format");
        deleteTree(work);
    }

    private static void testFailedMigrationKeepsLegacy() throws Exception {
        Path work = Path.of("test-work-migration-failure");
        deleteTree(work);
        Files.createDirectories(work);
        Path vaultPath = work.resolve("vault.dat");
        Vault vault = new Vault();
        vault.addSecret("Name", "value");
        SecretKey legacyKey = new SecretKeySpec(
                MessageDigest.getInstance("SHA-256").digest(PASSWORD.getBytes(StandardCharsets.UTF_8)),
                "AES");
        byte[] legacy = EncryptionUtils.encrypt(vault.convertToBytes(), legacyKey);
        Files.write(vaultPath, legacy);
        Files.createDirectory(Path.of(vaultPath + ".legacy.bak"));

        Vault loaded = new VaultStorage(vaultPath).loadVault(PASSWORD);
        check(loaded.secretExists("name"), "login must succeed when migration fails");
        check(java.util.Arrays.equals(legacy, Files.readAllBytes(vaultPath)),
                "failed migration must preserve the legacy vault");
        deleteTree(work);
    }

    private static void testFileDestinationIsNotOverwritten() throws Exception {
        Path work = Path.of("test-work-file");
        deleteTree(work);
        Files.createDirectories(work);
        Path destination = work.resolve("existing.bin");
        Files.writeString(destination, "original");
        Method writer = FileModule.class.getDeclaredMethod(
                "writeAtomically", Path.class, byte[].class);
        writer.setAccessible(true);
        try {
            writer.invoke(null, destination, "replacement".getBytes());
            throw new AssertionError("file destination must not be overwritten");
        } catch (InvocationTargetException expected) {
            check(expected.getCause() instanceof java.nio.file.FileAlreadyExistsException,
                    "existing destination error");
        }
        check("original".equals(Files.readString(destination)),
                "existing destination content must remain unchanged");
        deleteTree(work);
    }

    private static void expectFailure(ThrowingAction action, String message) throws Exception {
        try {
            action.run();
        } catch (Exception expected) {
            return;
        }
        throw new AssertionError(message);
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void deleteTree(Path root) throws Exception {
        if (Files.exists(root)) {
            try (var stream = Files.walk(root)) {
                stream.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try {
                        Files.deleteIfExists(path);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
            }
        }
    }

    @FunctionalInterface
    private interface ThrowingAction {
        void run() throws Exception;
    }
}
