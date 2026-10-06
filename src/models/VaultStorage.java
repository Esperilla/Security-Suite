package models;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

import static models.AuditLog.info;
import static models.AuditLog.warn;

/** Encrypted, authenticated and crash-safe persistence for the vault. */
public class VaultStorage {

    private static final Path DEFAULT_VAULT_PATH = determineVaultPath();
    private final Path vaultPath;
    private final Path backupPath;

    public VaultStorage() {
        this(DEFAULT_VAULT_PATH);
    }

    /** Constructor used by tests and by embedders that need another vault location. */
    public VaultStorage(Path vaultPath) {
        if (vaultPath == null) {
            throw new IllegalArgumentException("La ruta de la bóveda no puede ser nula.");
        }
        this.vaultPath = vaultPath.toAbsolutePath().normalize();
        this.backupPath = Paths.get(this.vaultPath + ".legacy.bak");
    }

    private static Path determineVaultPath() {
        try {
            Path classLocation = Paths.get(VaultStorage.class.getProtectionDomain()
                    .getCodeSource().getLocation().toURI());
            Path projectRoot = findProjectRoot(Files.isDirectory(classLocation)
                    ? classLocation : classLocation.getParent());
            return projectRoot.resolve("boveda.dat").toAbsolutePath().normalize();
        } catch (URISyntaxException | NullPointerException | SecurityException e) {
            return Paths.get("boveda.dat").toAbsolutePath().normalize();
        }
    }

    private static Path findProjectRoot(Path start) {
        Path current = start;
        while (current != null && !Files.isDirectory(current.resolve("src"))) {
            current = current.getParent();
        }
        return current == null ? start : current;
    }

    public boolean vaultExists() {
        return Files.isRegularFile(vaultPath, LinkOption.NOFOLLOW_LINKS);
    }

    public Vault loadVault(String password) throws Exception {
        if (!vaultExists()) {
            throw new IOException("No existe una bóveda configurada.");
        }
        byte[] encryptedData;
        try {
            encryptedData = Files.readAllBytes(vaultPath);
            FileSecurity.restrictToOwner(vaultPath);
        } catch (IOException e) {
            throw new IOException("No se pudo leer la bóveda.", e);
        }

        try {
            // Authentication, decryption and complete object validation all happen
            // before a legacy file is ever considered for migration.
            EncryptionUtils.DecryptionResult result =
                    EncryptionUtils.decryptWithPassword(encryptedData, password);
            Vault loadedVault = Vault.createFromBytes(result.data());
            if (result.legacy()) {
                migrateLegacyVaultBestEffort(loadedVault, password, result.data(), encryptedData);
            }
            info("Bóveda cargada correctamente.");
            return loadedVault;
        } catch (Exception e) {
            warn("Intento de descifrado o validación de bóveda fallido.");
            throw new Exception("Contraseña incorrecta o archivo dañado.", e);
        }
    }

    public void saveVault(Vault vault, String password) throws Exception {
        if (vault == null) {
            throw new IllegalArgumentException("La bóveda no puede ser nula.");
        }
        byte[] plainData = vault.convertToBytes();
        byte[] encryptedData = EncryptionUtils.encryptWithPassword(plainData, password);
        atomicWriteValidated(vaultPath, encryptedData, password, plainData, true);
        info("Bóveda guardada correctamente.");
    }

    private void migrateLegacyVaultBestEffort(Vault vault, String password,
                                               byte[] plainData, byte[] legacyData) {
        try {
            byte[] encryptedData = EncryptionUtils.encryptWithPassword(plainData, password);
            atomicWriteValidated(vaultPath, encryptedData, password, plainData, true,
                    legacyData);
            info("Bóveda antigua migrada al formato de cifrado actual.");
        } catch (Exception e) {
            // A successful login must never be turned into a failed login by migration.
            warn("No se pudo migrar la bóveda antigua; se conserva el archivo original.");
        }
    }

    private void atomicWriteValidated(Path destination, byte[] data, String password,
                                      byte[] expectedPlainData, boolean replace)
            throws Exception {
        atomicWriteValidated(destination, data, password, expectedPlainData, replace, null);
    }

    private void atomicWriteValidated(Path destination, byte[] data, String password,
                                      byte[] expectedPlainData, boolean replace,
                                      byte[] legacyData) throws Exception {
        Path parent = validateDestination(destination, replace);
        Path temporary = writeTemporary(parent, destination.getFileName().toString(), data);
        boolean moved = false;
        try {
            validateNewVault(temporary, password, expectedPlainData);
            if (legacyData != null) {
                createProtectedLegacyBackup(legacyData);
            }
            publish(temporary, destination, replace);
            moved = true;
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private Path validateDestination(Path destination, boolean replace) throws IOException {
        Path normalized = destination.toAbsolutePath().normalize();
        if (Files.isSymbolicLink(normalized)) {
            throw new IOException("La ruta de destino no puede ser un enlace simbólico.");
        }
        Path parent = normalized.getParent();
        if (parent == null) {
            throw new IOException("No se pudo determinar la carpeta de la bóveda.");
        }
        Files.createDirectories(parent);
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("La carpeta de destino no es válida.");
        }
        if (Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)
                && !Files.isRegularFile(normalized, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("El destino no es un archivo regular.");
        }
        if (!replace && Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            throw new FileAlreadyExistsException(normalized.toString());
        }
        return parent;
    }

    private static Path writeTemporary(Path parent, String prefix, byte[] data) throws IOException {
        Path temporary = Files.createTempFile(parent, prefix + ".", ".tmp");
        boolean complete = false;
        try {
            FileSecurity.restrictToOwner(temporary);
            try (FileChannel channel = FileChannel.open(temporary,
                    StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            FileSecurity.restrictToOwner(temporary);
            complete = true;
            return temporary;
        } finally {
            if (!complete) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private static void validateNewVault(Path file, String password, byte[] expectedPlainData)
            throws Exception {
        byte[] encrypted = Files.readAllBytes(file);
        EncryptionUtils.DecryptionResult result =
                EncryptionUtils.decryptWithPassword(encrypted, password);
        if (result.legacy() || !Arrays.equals(expectedPlainData, result.data())) {
            throw new IOException("La validación de la bóveda temporal falló.");
        }
        Vault reconstructed = Vault.createFromBytes(result.data());
        if (!Arrays.equals(expectedPlainData, reconstructed.convertToBytes())) {
            throw new IOException("La reconstrucción de la bóveda temporal falló.");
        }
    }

    private void createProtectedLegacyBackup(byte[] legacyData) throws IOException {
        if (Files.exists(backupPath, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.isRegularFile(backupPath, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("El respaldo legacy existente no es un archivo regular.");
            }
            return;
        }
        Path parent = backupPath.getParent();
        if (parent == null) {
            throw new IOException("No se pudo determinar la carpeta del respaldo.");
        }
        Files.copy(vaultPath, backupPath);
        FileSecurity.restrictToOwner(backupPath);
        if (!Arrays.equals(legacyData, Files.readAllBytes(backupPath))) {
            throw new IOException("No se pudo verificar el respaldo legacy.");
        }
    }

    private static void publish(Path temporary, Path destination, boolean replace) throws IOException {
        try {
            if (replace) {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
            }
        } catch (AtomicMoveNotSupportedException e) {
            if (replace) {
                Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
            } else {
                Files.move(temporary, destination);
            }
        }
        FileSecurity.restrictToOwner(destination);
        FileSecurity.forceDirectory(destination.toAbsolutePath().getParent());
    }
}
