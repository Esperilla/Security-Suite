package models;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/** Best-effort filesystem hardening shared by encrypted data and audit logs. */
public final class FileSecurity {

    private FileSecurity() {
    }

    public static void restrictToOwner(Path path) {
        try {
            if (Files.getFileAttributeView(path,
                    java.nio.file.attribute.PosixFileAttributeView.class) != null) {
                Set<PosixFilePermission> permissions = EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE);
                Files.setPosixFilePermissions(path, permissions);
            }
        } catch (IOException | UnsupportedOperationException | SecurityException ignored) {
            // Windows and filesystems without POSIX permissions are handled by the OS.
        }
    }

    public static void forceDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException | SecurityException ignored) {
            // Directory fsync is not supported on every platform.
        }
    }
}
