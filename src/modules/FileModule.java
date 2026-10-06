package modules;

import models.AuditLog;
import models.EncryptionUtils;
import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.util.Locale;
import java.util.Arrays;
import models.FileSecurity;

public class FileModule extends BaseModule {

    private final String password;

    public FileModule(String password, Console console) {
        super(console);
        this.password = password;
    }

    @Override
    public String getName() {
        return "Cifrador de Archivos";
    }

    @Override
    public void execute() throws Exception {
        boolean continueRunning = true;
        while (continueRunning) {
            System.out.println("\n--- " + getName() + " ---");
            System.out.println("1. Cifrar archivo");
            System.out.println("2. Descifrar archivo");
            System.out.println("3. Regresar");
            System.out.print("> ");

            int option = readOption();
            if (isInputEnded()) {
                return;
            }

            switch (option) {
                case 1: processFile(true); break;
                case 2: processFile(false); break;
                case 3: continueRunning = false; break;
                default: System.out.println("Opción inválida.");
            }
        }
    }

    private void processFile(boolean encrypting) {
        System.out.print("Ruta del archivo (usa / en lugar de \\ y sin comillas): ");
        String pathText = readLine();

        if (pathText.isEmpty()) {
            System.out.println("Error: No se ingresó ninguna ruta.");
            return;
        }

        // Trim leading and trailing spaces
        pathText = pathText.trim();

        try {
            Path filePath = Paths.get(pathText);

            // Convert relative paths to absolute paths
            if (!filePath.isAbsolute()) {
                filePath = filePath.toAbsolutePath();
            }
            filePath = filePath.normalize();

            if (!Files.exists(filePath)) {
                AuditLog.error("Archivo no encontrado: " + filePath.getFileName());
                System.out.println("Error: Archivo no encontrado.");
                System.out.println("Ruta buscada: " + filePath);
                return;
            }

            if (Files.isDirectory(filePath)) {
                System.out.println("Error: La ruta corresponde a un directorio, no a un archivo.");
                return;
            }

            // Basic extension validation
            boolean hasLockedExtension = filePath.getFileName().toString()
                    .toLowerCase(Locale.ROOT).endsWith(".locked");

            if (encrypting && hasLockedExtension) {
                AuditLog.warn("Archivo '" + filePath.getFileName() + "' ya tiene extensión .locked.");
                System.out.println("El archivo ya parece estar cifrado.");
                return;
            }
            if (!encrypting && !hasLockedExtension) {
                AuditLog.warn("Extensión inválida para descifrar: " + filePath.getFileName());
                System.out.println("Para descifrar, el archivo debe terminar en .locked");
                return;
            }

            // 1. Read file
            byte[] inputData = Files.readAllBytes(filePath);
            Path outputPath;

            String absolutePath = filePath.toString();

            if (encrypting) {
                outputPath = Paths.get(absolutePath + ".locked");
            } else {
                // Remove the extension while preserving the original casing.
                String originalName = absolutePath.substring(0, absolutePath.length() - ".locked".length());
                outputPath = Paths.get(originalName);
            }

            if (Files.exists(outputPath)) {
                AuditLog.warn("Destino existente rechazado: " + outputPath.getFileName());
                System.out.println("Error: El archivo de destino ya existe; no se sobrescribirá.");
                return;
            }

            byte[] outputData;
            if (encrypting) {
                outputData = EncryptionUtils.encryptWithPassword(inputData, password);
            } else {
                outputData = EncryptionUtils.decryptWithPassword(inputData, password).data();
            }

            // Write beside the destination and publish it atomically. The
            // source is deleted only after the output has been published.
            writeAtomically(outputPath, outputData);
            try {
                validateOutput(outputPath, inputData, outputData, encrypting);
            } catch (Exception validationError) {
                Files.deleteIfExists(outputPath);
                throw validationError;
            }
            try {
                Files.delete(filePath);
            } catch (IOException deleteError) {
                AuditLog.warn("Archivo convertido pero no se pudo eliminar el original: "
                        + filePath.getFileName());
                System.out.println("Advertencia: el archivo nuevo se creó, pero no se pudo eliminar el original.");
                return;
            }

            String operation = encrypting ? "cifrado" : "descifrado";
            AuditLog.info("Archivo '" + filePath.getFileName() + "' " + operation + " correctamente.");
            System.out.println("Éxito. Archivo original eliminado.");
            System.out.println("Nuevo archivo: " + outputPath);

        } catch (Exception e) {
            String operation = encrypting ? "cifrar" : "descifrar";
            AuditLog.error("Error al " + operation + " archivo: " + e.getMessage());
            System.out.println("Error: " + e.getMessage());
        }
    }

    private static void writeAtomically(Path destination, byte[] data) throws IOException {
        Path parent = destination.toAbsolutePath().getParent();
        if (parent == null) {
            throw new IOException("No se pudo determinar la carpeta de destino.");
        }
        if (Files.isSymbolicLink(destination)
                || Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw new FileAlreadyExistsException(destination.toString());
        }
        Files.createDirectories(parent);
        if (!Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("La carpeta de destino no es válida.");
        }
        Path temporary = Files.createTempFile(parent, "secure-output-", ".tmp");
        boolean moved = false;
        try {
            FileSecurity.restrictToOwner(temporary);
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(data);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            FileSecurity.restrictToOwner(temporary);
            try {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, destination);
            }
            moved = true;
            FileSecurity.restrictToOwner(destination);
            FileSecurity.forceDirectory(parent);
        } finally {
            if (!moved) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    private void validateOutput(Path output, byte[] sourceData, byte[] outputData,
                                boolean encrypting) throws Exception {
        byte[] publishedData = Files.readAllBytes(output);
        if (encrypting) {
            byte[] recovered = EncryptionUtils.decryptWithPassword(publishedData, password).data();
            if (!Arrays.equals(sourceData, recovered)) {
                throw new IOException("La validación del archivo cifrado falló.");
            }
        } else if (!Arrays.equals(outputData, publishedData)) {
            throw new IOException("La validación del archivo descifrado falló.");
        }
    }
}
