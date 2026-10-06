package models;

import java.io.*;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static models.AuditLog.*;

/**
 * Represents the vault in memory.
 * Stores text only (String, String).
 * String: secret name, String: secret value.
 */
public class Vault implements Serializable {

    @Serial
    private static final long serialVersionUID = 20L;

    // Simple String-to-String map
    // Map stores key-value pairs
    private final LinkedHashMap<String, String> secrets;
    public static final int MAX_SECRET_NAME_LENGTH = 100;
    public static final int MAX_SECRET_VALUE_LENGTH = 10_000;
    public static final int MAX_SEARCH_LENGTH = 100;
    public static final int MAX_SEARCH_RESULTS = 10;

    public Vault() {
        this.secrets = new LinkedHashMap<>();
    }

    // --- Management methods ---

    public void addSecret(String name, String value) {
        String cleanName = validateSecret(name, value);
        if (findKey(cleanName) != null) {
            throw new IllegalArgumentException("Ya existe un secreto con ese nombre (sin distinguir mayúsculas).");
        }
        secrets.put(cleanName, value);
        info("Se agregó un secreto '" + name + "'.");
        System.out.println("Secreto '" + name + "' agregado.");
    }

    public String getSecret(String name) {
        String key = findKey(name);
        if (key != null) {
            info("Se consultó el secreto '" + key + "'.");
            return secrets.get(key);
        } else {
            warn("Secreto '" + name + "' no encontrado.");
            return "Error: Secreto no encontrado.";
        }
    }

    public Set<String> listSecretNames() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(secrets.keySet()));
    }

    public void deleteSecret(String name) {
        String key = findKey(name);
        if (key != null) {
            secrets.remove(key);
            info("Se eliminó el secreto '" + key + "'.");
            System.out.println("🗑️ Secreto '" + key + "' eliminado.");
        } else {
            warn("Intento de eliminar secreto '" + name + "' que no existe.");
            System.out.println("Error: No se encontró el secreto '" + name + "'.");
        }
    }

    /**
     * Checks whether a secret exists in the vault.
     *
     * @param name secret name to check
     * @return true if the secret exists, false otherwise
     */
    public boolean secretExists(String name) {
        return findKey(name) != null;
    }

    /**
     * Updates the value of an existing secret.
     *
     * @param name name of the secret to update
     * @param newValue new value for the secret
     * @return true if updated successfully, false if the secret does not exist
     */
    public boolean updateSecret(String name, String newValue) {
        validateSecret(name, newValue);
        String key = findKey(name);
        if (key == null) {
            warn("Intento de actualizar secreto '" + name + "' que no existe.");
            System.out.println("Error: El secreto '" + name + "' no existe.");
            return false;
        }

        secrets.put(key, newValue);
        info("Se actualizó el secreto '" + key + "'.");
        System.out.println("✔ Secreto '" + key + "' actualizado correctamente.");
        return true;
    }

    private static String validateSecret(String name, String value) {
        if (name == null || name.trim().isEmpty()) {
            throw new IllegalArgumentException("El nombre del secreto no puede estar vacío.");
        }
        String cleanName = name.trim();
        if (cleanName.length() > MAX_SECRET_NAME_LENGTH) {
            throw new IllegalArgumentException("El nombre del secreto no puede superar "
                    + MAX_SECRET_NAME_LENGTH + " caracteres.");
        }
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("El valor del secreto no puede estar vacío.");
        }
        if (value.length() > MAX_SECRET_VALUE_LENGTH) {
            throw new IllegalArgumentException("El valor del secreto no puede superar "
                    + MAX_SECRET_VALUE_LENGTH + " caracteres.");
        }
        return cleanName;
    }

    private String findKey(String name) {
        if (name == null) {
            return null;
        }
        String wanted = name.trim().toLowerCase(Locale.ROOT);
        for (String key : secrets.keySet()) {
            if (key.toLowerCase(Locale.ROOT).equals(wanted)) {
                return key;
            }
        }
        return null;
    }

    // --- Smart search methods ---

    /**
     * Calculates the Levenshtein distance between two strings.
     * The distance is the minimum number of operations (insertion, deletion, substitution)
     * needed to transform one string into another.
     *
     * @param a first string
     * @param b second string
     * @return edit distance between the two strings
     */
    private int calculateLevenshteinDistance(String a, String b) {
        a = a.toLowerCase(Locale.ROOT);
        b = b.toLowerCase(Locale.ROOT);
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            int rowMinimum = current[0];
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(Math.min(previous[j] + 1, current[j - 1] + 1),
                        previous[j - 1] + cost);
                rowMinimum = Math.min(rowMinimum, current[j]);
            }
            if (rowMinimum > MAX_SEARCH_RESULTS) {
                return MAX_SEARCH_RESULTS + 1;
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return previous[b.length()];
    }

    /**
     * Calculates a similarity score for sorting results.
     * Lower score means higher relevance.
     * Priority: exact match > contains > close Levenshtein match
     *
     * @param secretName stored secret name
     * @param pattern user's search pattern
     * @return similarity score (lower is better)
     */
    private int calculateSimilarityScore(String secretName, String pattern) {
        String nameLower = secretName.toLowerCase(Locale.ROOT);
        String patternLower = pattern.toLowerCase(Locale.ROOT);
        
        // Exact match (highest priority)
        if (nameLower.equals(patternLower)) {
            return 0;
        }
        
        // Starts with the pattern
        if (nameLower.startsWith(patternLower)) {
            return 1;
        }
        
        // Contains the pattern
        if (nameLower.contains(patternLower)) {
            return 2;
        }
        
        // Levenshtein distance (adjusted for sorting)
        int distance = calculateLevenshteinDistance(secretName, pattern);
        return 10 + distance; // Base of 10 gives contains higher priority
    }

    /**
     * Searches for secrets intelligently using multiple strategies:
     * 1. Exact match (ignoring case)
     * 2. Partial match (contains the pattern)
     * 3. Levenshtein similarity (tolerance for typos)
     *
     * @param pattern search pattern entered by the user
     * @param maxResults maximum number of results to return
     * @return list of secret names sorted by relevance
     */
    public List<String> searchSecretsIntelligently(String pattern, int maxResults) {
        if (pattern == null || pattern.trim().isEmpty() || maxResults <= 0) {
            return new ArrayList<>();
        }
        String patternLower = pattern.trim().toLowerCase(Locale.ROOT);
        if (patternLower.length() > MAX_SEARCH_LENGTH) {
            return new ArrayList<>();
        }
        int resultLimit = Math.min(maxResults, MAX_SEARCH_RESULTS);
        
        // Dynamic threshold based on pattern length:
        // - 1-2 characters: exact or contains only (threshold 0)
        // - 3-4 characters: allow 1 typo
        // - 5-7 characters: allow 2 typos
        // - 8+ characters: allow 3 typos
        int levenshteinThreshold;
        if (patternLower.length() <= 2) {
            levenshteinThreshold = 0; // Exact or contains only for very short searches
        } else if (patternLower.length() <= 4) {
            levenshteinThreshold = 1;
        } else if (patternLower.length() <= 7) {
            levenshteinThreshold = 2;
        } else {
            levenshteinThreshold = 3;
        }
        
        final int finalThreshold = levenshteinThreshold;
        
        // Filter secrets matching at least one criterion
        List<String> results = secrets.keySet().stream()
            .filter(name -> name != null && !name.trim().isEmpty()) // Ignore empty names
            .filter(name -> {
                String nameLower = name.toLowerCase(Locale.ROOT).trim();
                // Include exact matches, contained patterns, or Levenshtein distance <= threshold
                boolean exactMatch = nameLower.equals(patternLower);
                boolean containsPattern = nameLower.contains(patternLower);
                boolean closeLevenshtein = finalThreshold > 0 &&
                    calculateLevenshteinDistance(nameLower, patternLower) <= finalThreshold;
                
                return exactMatch || containsPattern || closeLevenshtein;
            })
            .sorted(Comparator.comparingInt(name -> calculateSimilarityScore(name, patternLower)))
            .limit(resultLimit)
            .collect(Collectors.toList());
        
        return results;
    }

    // --- Serialization methods (byte conversion) ---

    public byte[] convertToBytes() throws IOException {
        // Use try-with-resources to close streams automatically
        try (ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
             ObjectOutputStream objectStream = new ObjectOutputStream(byteStream)) {

            objectStream.writeObject(this.secrets); // Store the map
            objectStream.flush(); // Ensure all data is written
            return byteStream.toByteArray();
        }
    }

    public static Vault createFromBytes(byte[] data) throws Exception {
        if (data == null || data.length == 0) {
            throw new IOException("Los datos de la bóveda están vacíos.");
        }

        try (ByteArrayInputStream byteIn = new ByteArrayInputStream(data);
             ObjectInputStream objIn = new ObjectInputStream(byteIn)) {

            objIn.setObjectInputFilter(info -> {
                if (info.depth() > 20 || info.references() > 10_000
                        || info.streamBytes() > 10_485_760) {
                    return java.io.ObjectInputFilter.Status.REJECTED;
                }
                Class<?> type = info.serialClass();
                if (type == null) {
                    return java.io.ObjectInputFilter.Status.UNDECIDED;
                }
                if (type == String.class
                        || type.getName().startsWith("java.util.")
                        || (type.isArray() && type.getComponentType() != null
                        && (type.getComponentType() == String.class
                        || type.getComponentType().getName().startsWith("java.util.")))) {
                    return java.io.ObjectInputFilter.Status.ALLOWED;
                }
                return java.io.ObjectInputFilter.Status.REJECTED;
            });
            Object obj = objIn.readObject();

            if (obj instanceof Map<?, ?> raw) {
            Vault newVault = new Vault();
            for (Map.Entry<?, ?> entry : raw.entrySet()) {
                Object k = entry.getKey();
                Object v = entry.getValue();
                if (!(k instanceof String) || !(v instanceof String)) {
                    throw new IOException("El Map contiene claves/valores que no son String.");
                }
                String cleanName = validateSecret((String) k, (String) v);
                if (newVault.findKey(cleanName) != null) {
                    throw new IOException("La bóveda contiene nombres duplicados.");
                }
                newVault.secrets.put(cleanName, (String) v);
            }
                return newVault;
            } else {
                throw new IOException("Los datos no contienen un Map válido.");
            }
        }
    }
}
