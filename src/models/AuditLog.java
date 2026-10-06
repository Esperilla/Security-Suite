package models;


import java.io.*;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Event logging system for auditing.
 * Records actions with date and time in logs/audit.log
 *
 * Line format: [YYYY-MM-DD HH:mm:ss] Level: message
 * Example: [2025-11-20 10:00:00] INFO: secret 'Gmail' was added.
 *
 * Important: only secret names are recorded, NEVER sensitive values.
 */
public class AuditLog {
    private static final String LOG_DIRECTORY = "logs";
    private static final String LOG_FILE = "audit.log";
    private static final int RETENTION_DAYS = 7;
    private static final long MAX_LOG_BYTES = 1_048_576;

    // Date/time formatters
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");

    // Flag to run cleanup only once per session
    private static boolean cleanupExecuted = false;

    // Calculated log file path
    private static final String LOG_FILE_PATH;

    static {
        String calculatedPath;
        // Get the classpath base location
        try {
            File classLocation = new File(
                    AuditLog.class.getProtectionDomain()
                            .getCodeSource()
                            .getLocation()
                            .toURI()
            );

            File projectRoot = classLocation;
            while (projectRoot.getParentFile() != null
                    && !new File(projectRoot, "src").isDirectory()) {
                projectRoot = projectRoot.getParentFile();
            }

            // Create the logs directory if it does not exist
            File logsDirectory = new File(projectRoot, LOG_DIRECTORY);
            if(!logsDirectory.exists()){
                logsDirectory.mkdirs();
            }

            calculatedPath = new File(logsDirectory, LOG_FILE).getAbsolutePath();
            FileSecurity.restrictToOwner(new File(calculatedPath).toPath());
        }catch (URISyntaxException | NullPointerException e){
            // Fall back to a relative path if detection fails
            File logsDirectory = new File(LOG_DIRECTORY);
            if (!logsDirectory.exists()){
                logsDirectory.mkdirs();
            }
            calculatedPath = new File(logsDirectory, LOG_FILE).getAbsolutePath();
        }
        LOG_FILE_PATH = calculatedPath;
    }

    /**
     * Records an INFO-level event.
     * Use for successful and normal operations.
     *
     * @param message event description (do not include sensitive values)
     **/
    public static void info(String message){
        record("INFO", message);
    }

    /**
     * Records a WARN-level event.
     * Use for warnings and situations requiring attention.
     *
     * @param message event description (do not include sensitive values)
     */
    public static void warn(String message) {
        record("WARN", message);
    }

    /**
     * Records an ERROR-level event.
     * Use for errors and system failures.
     *
     * @param message event description (do not include sensitive values)
     */
    public static void error(String message) {
        record("ERROR", message);
    }

    /**
     * Main logging method.
     * Formats and writes the line to the file.
     * Cleans old logs once per session.
     *
     * @param level event level (INFO, WARN, ERROR)
     * @param message event description
     */

    private static synchronized void record(String level, String message){
        // Run cleanup once per session
        if(!cleanupExecuted){
            cleanOldLogs();
            cleanupExecuted = true;
        }
        rotateIfNeeded();
        // Format line: [2025-11-28 10:00:00] INFO: message
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String safeLevel = sanitize(level);
        String safeMessage = sanitize(message);
        String line = String.format("[%s] %s: %s", timestamp, safeLevel, safeMessage);

        // Write to the file (append mode)
        Path logPath = Path.of(LOG_FILE_PATH);
        try {
            if (Files.isSymbolicLink(logPath)) {
                throw new IOException("La bitácora no puede ser un enlace simbólico.");
            }
        } catch (IOException e) {
            System.err.println("[AuditLog] Error al validar log: " + e.getMessage());
            return;
        }
        try (BufferedWriter writer = Files.newBufferedWriter(logPath,
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND)) {
            writer.write(line);
            writer.newLine();
            writer.flush();
            FileSecurity.restrictToOwner(logPath);

        } catch (IOException e) {
            // Logging must not interrupt the application
            System.err.println("[AuditLog] Error al escribir log: " + e.getMessage());
        }
    }

    private static void rotateIfNeeded() {
            Path path = Path.of(LOG_FILE_PATH);
            try {
                if (Files.isSymbolicLink(path)
                        || !Files.exists(path) || Files.size(path) < MAX_LOG_BYTES) {
                    return;
                }
                Path rotated = path.resolveSibling(LOG_FILE + ".1");
                Files.move(path, rotated, StandardCopyOption.REPLACE_EXISTING);
                FileSecurity.restrictToOwner(rotated);
            } catch (IOException e) {
                System.err.println("[AuditLog] Error al rotar logs: " + e.getMessage());
            }
    }

    /**
     * Prevents user-controlled names and exception messages from forging
     * additional audit entries or writing terminal control characters.
     */
    private static String sanitize(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder result = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c == '\r' || c == '\n' || c == '\t') {
                result.append(' ');
            } else if (!Character.isISOControl(c)) {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Removes log lines older than 7 days.
     * Reads the file, filters old lines, and rewrites the file.
     */

    private static void cleanOldLogs(){
        File logFile = new File(LOG_FILE_PATH);

        // If the file does not exist, there is nothing to clean
        if (!logFile.exists()) {
            return;
        }

        try{
            // Read all lines
            List<String> lines = Files.readAllLines(logFile.toPath());
            List<String> validLines = new ArrayList<>();

            LocalDate cutoffDate = LocalDate.now().minusDays(RETENTION_DAYS);

            for (String line : lines) {
                // Extract date from the line [YYYY-MM-DD HH:mm:ss]
                LocalDate lineDate = extractDateFromLine(line);

                // Keep the line if no date could be extracted or it is within the retention period
                if (lineDate == null || !lineDate.isBefore(cutoffDate)) {
                    validLines.add(line);
                }
            }

            // Rewrite only if there were changes
            if (validLines.size() < lines.size()) {
                Files.write(logFile.toPath(), validLines, StandardOpenOption.CREATE,
                        StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
                FileSecurity.restrictToOwner(logFile.toPath());
            }

        } catch (IOException e) {
            // Logging must not interrupt the application
            System.err.println("[AuditLog] Error al limpiar logs antiguos: " + e.getMessage());
        }
    }

    /**
     * Extracts the date from a log line.
     * Expected format: [YYYY-MM-DD HH:mm:ss] ...
     *
     * @param line log file line
     * @return extracted LocalDate or null if it cannot be parsed
     */

    private static LocalDate extractDateFromLine(String line){
        if (line == null || line.length() < 12){
            return null;
        }
        try {
            // Extract only the date portion [YYYY-MM-DD
            if (line.startsWith("[") && line.length() >= 11) {
                String dateString = line.substring(1, 11); // "YYYY-MM-DD"
                return LocalDate.parse(dateString, DATE_FORMAT);
            }
        }catch (DateTimeParseException e){
            // Invalid line format, return null
        }
        return null;
    }



}
