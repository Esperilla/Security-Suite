package modules;

import models.Vault;
import models.VaultStorage;
import models.EncryptionUtils;
import java.io.Console;
import java.util.List;
import models.AuditLog;

public class VaultModule extends BaseModule {

    private static final int MAX_PASSWORD_ATTEMPTS = 3;

    private final Vault vault;
    private final VaultStorage storage;
    private String password; // Not final to allow password changes
    private boolean dirty;

    public VaultModule(Vault vault, VaultStorage storage, String password, Console console) {
        super(console);
        this.vault = vault;
        this.storage = storage;
        this.password = password;
    }

    @Override
    public String getName() {
        return "Gestor de Contraseñas";
    }

    /**
     * Gets the current password (it may have changed during the session).
     */
    public String getPassword() {
        return password;
    }

    public boolean hasPendingChanges() {
        return dirty;
    }

    public boolean savePendingChanges() {
        if (!dirty) {
            return true;
        }
        try {
            storage.saveVault(vault, password);
            dirty = false;
            System.out.println("Cambios pendientes guardados.");
            return true;
        } catch (Exception e) {
            AuditLog.error("No se pudieron guardar los cambios pendientes: " + e.getMessage());
            System.out.println("Error al guardar cambios pendientes: " + e.getMessage());
            return false;
        }
    }

    @Override
    public void execute() throws Exception {
        boolean continueRunning = true;
        while (continueRunning) {
            System.out.println("\n--- " + getName() + " ---");

            boolean isEmpty = vault.listSecretNames().isEmpty();

            // Dynamic menu
            System.out.println("1. Agregar secreto");
            if (isEmpty) {
                System.out.println("2. Cambiar contraseña maestra");
                System.out.println("3. Guardar y Regresar");
            } else {
                System.out.println("2. Ver secreto");
                System.out.println("3. Listar secretos");
                System.out.println("4. Eliminar secreto");
                System.out.println("5. Actualizar secreto");        
                System.out.println("6. Cambiar contraseña maestra");       
                System.out.println("7. Guardar y Regresar");      
            }
            System.out.print("> ");

            int option = readOption();
            if (isInputEnded()) {
                savePendingChanges();
                return;
            }

            // Adjust the logic when empty so the menu remains consistent
            if (isEmpty) {
                // Empty menu: 1=Add, 2=Change password, 3=Save
                if (option == 2) option = 6;
                else if (option == 3) option = 7;
                else if (option != 1) option = -1;
            }

            switch (option) {
                case 1:
                    System.out.print("Nombre del secreto: ");
                    String name = readLine();
                    System.out.print("Valor del secreto: ");
                    String value = readLine();
                    if (isInputEnded()) {
                        savePendingChanges();
                        return;
                    }
                    if (name.trim().isEmpty() || value.isEmpty()) {
                        System.out.println("Error: el nombre y el valor no pueden estar vacíos.");
                        break;
                    }
                    try {
                        vault.addSecret(name, value);
                        dirty = true;
                    } catch (IllegalArgumentException e) {
                        System.out.println("Error: " + e.getMessage());
                    }
                    break;
                case 2:
                    System.out.print("Buscar secreto: ");
                    String search = readLine();
                    searchAndShowSecret(search);
                    break;
                case 3:
                    System.out.println("--- Lista de Secretos ---");
                    vault.listSecretNames().forEach(System.out::println);
                    break;
                case 4:
                    System.out.print("Nombre a eliminar: ");
                    String nameToDelete = readLine();
                    if (isInputEnded()) {
                        savePendingChanges();
                        return;
                    }
                    boolean existed = vault.secretExists(nameToDelete);
                    Boolean deleteConfirmed = readConfirmation(
                            "¿Desea eliminar este secreto? (S/N): ");
                    if (deleteConfirmed == null) {
                        savePendingChanges();
                        return;
                    }
                    if (!deleteConfirmed) {
                        System.out.println("Operación cancelada.");
                        break;
                    }
                    vault.deleteSecret(nameToDelete);
                    dirty |= existed;
                    break;
                case 5:
                    updateSecret();
                    break;      
                case 6:     
                    changeMasterPassword();
                    break;
                case 7:     
                    System.out.println("Guardando...");
                    if (savePendingChanges() || !dirty) {
                        System.out.println("¡Guardado! Regresando...");
                        continueRunning = false;
                    }
                    break;
                default:
                    System.out.println("Opción inválida.");
            }
        }
    }

    /**
     * Changes the vault master password.
     * Validates the current password (maximum 3 attempts), applies the security policy
     * to the new password, and re-encrypts the vault.
     *
     * @return true if the change succeeded, false if it was cancelled or failed
     */
    public boolean changeMasterPassword() {
        System.out.println("\n--- Cambiar Contraseña Maestra ---");

        // Step 1: Verify the current password (maximum 3 attempts)
        int attempts = 0;
        boolean passwordVerified = false;

        while (attempts < MAX_PASSWORD_ATTEMPTS && !passwordVerified) {
            String enteredPassword = readHiddenPassword("Ingrese su contraseña actual: ");
            if (isInputEnded()) {
                return false;
            }

            try {
                // Load the vault to verify the password
                storage.loadVault(enteredPassword);
                passwordVerified = true;
            } catch (Exception e) {
                attempts++;
                int remaining = MAX_PASSWORD_ATTEMPTS - attempts;
                if (remaining > 0) {
                    AuditLog.warn("Contraseña incorrecta al cambiar contraseña maestra. Intentos restantes: " + remaining);
                    System.out.println("⚠ Contraseña incorrecta. Intentos restantes: " + remaining);
                } else {
                    AuditLog.warn("Se agotaron los intentos de cambio de contraseña maestra.");
                    System.out.println("\n✖ Se agotaron los intentos. Operación cancelada por seguridad.");
                    return false;
                }
            }
        }

        // Step 2: Show requirements and warning
        System.out.println();
        System.out.println(EncryptionUtils.PASSWORD_REQUIREMENTS);
        System.out.println();
        System.out.println("⚠ ADVERTENCIA: Los archivos .locked cifrados con el Cifrador de Archivos");
        System.out.println("  seguirán usando la contraseña anterior. Descífrelos antes de cambiar");
        System.out.println("  la contraseña o recuerde la contraseña antigua.");
        System.out.println();

        // Step 3: Request and validate the new password
        String newPassword;
        String validationError = null;

        do {
            newPassword = readHiddenPassword("Nueva contraseña: ");
            if (isInputEnded()) {
                return false;
            }

            // Verify that it differs from the current password
            if (newPassword.equals(password)) {
                System.out.println("\n⚠ La nueva contraseña no puede ser igual a la actual.");
                System.out.println("Intenta de nuevo.\n");
                validationError = "igual"; // Marker to continue the loop
                continue;
            }

            validationError = EncryptionUtils.validatePasswordPolicy(newPassword);

            if (validationError != null) {
                System.out.println("\n⚠ " + validationError);
                System.out.println("Intenta de nuevo.\n");
            }
        } while (validationError != null);

        // Step 4: Confirm the new password
        String confirmation;
        while (true) {
            confirmation = readHiddenPassword("Confirme la nueva contraseña: ");
            if (isInputEnded()) {
                return false;
            }
            if (newPassword.equals(confirmation)) {
                break;
            }
            AuditLog.warn("Confirmación de cambio de contraseña no coincidente.");
            System.out.println("\n⚠ Las contraseñas no coinciden. Inténtalo de nuevo.");
        }

        // Step 5: Re-encrypt the vault with the new password
        try {
            storage.saveVault(vault, newPassword);
            this.password = newPassword;
            dirty = false;
            AuditLog.info("Contraseña maestra cambiada exitosamente. ");
            System.out.println("\n✔ ¡Contraseña maestra cambiada exitosamente!");
            return true;
        } catch (Exception e) {
            AuditLog.error("Erro al cambiar contraseña maestra: " + e.getMessage());
            System.out.println("\n✖ Error al guardar la bóveda: " + e.getMessage());
            System.out.println("La contraseña NO fue cambiada.");
            return false;
        }
    }

    /**
     * Reads a password while hiding the user's input.
     */
    private String readHiddenPassword(String message) {
        if (console == null) {
            markInputEnded();
            return "";
        }
        char[] passwordArray = console.readPassword(message);
        if (passwordArray == null) {
            markInputEnded();
            return "";
        }
        if (passwordArray.length == 0) {
            return "";
        }
        String result = new String(passwordArray);
        // Clear the array for security
        java.util.Arrays.fill(passwordArray, '\0');
        return result;
    }

    /**
     * Searches for secrets intelligently and shows the results to the user.
     * If there are multiple matches, allows selecting which one to view.
     * Uses the Levenshtein algorithm to tolerate typos.
     *
     * @param pattern search pattern entered by the user
     */
    private void searchAndShowSecret(String pattern) {
        List<String> results = vault.searchSecretsIntelligently(pattern, 10);

        if (results.isEmpty()) {
            System.out.println("\n⚠ No se encontraron secretos que coincidan con '" + pattern + "'.");
            System.out.println("Sugerencia: Use la opción 'Listar secretos' para ver todos los disponibles.");
            return;
        }

        // Show directly when there is exactly one match
        if (results.size() == 1) {
            String secretName = results.get(0);
            System.out.println("\n✔ Secreto encontrado: " + secretName);
            System.out.println("Valor: " + vault.getSecret(secretName));
            return;
        }

        // Multiple matches: show the list and allow selection
        System.out.println("\n🔍 Se encontraron " + results.size() + " coincidencias:");
        System.out.println("───────────────────────────────");
        for (int i = 0; i < results.size(); i++) {
            System.out.println((i + 1) + ". " + results.get(i));
        }
        System.out.println("0. Cancelar búsqueda");
        System.out.println("───────────────────────────────");

        System.out.print("Seleccione un número: ");
        int selection = readOption();

        if (selection == 0) {
            System.out.println("Búsqueda cancelada.");
            return;
        }

        if (selection < 1 || selection > results.size()) {
            System.out.println("⚠ Selección inválida.");
            return;
        }

        String selectedName = results.get(selection - 1);
        System.out.println("\n✔ Secreto: " + selectedName);
        System.out.println("Valor: " + vault.getSecret(selectedName));
    }

    /**     
     * Updates the value of an existing secret.
     * Uses smart search to find the secret and requests confirmation
     * before updating it.
     */
    private void updateSecret() {
        System.out.print("Buscar secreto a actualizar: ");
        String pattern = readLine();

        List<String> results = vault.searchSecretsIntelligently(pattern, 10);

        if (results.isEmpty()) {
            System.out.println("\n⚠ No se encontraron secretos que coincidan con '" + pattern + "'.");
            System.out.println("Sugerencia: Use la opción 'Listar secretos' para ver todos los disponibles.");
            return;
        }

        String secretName;

        // Use directly when there is exactly one match
        if (results.size() == 1) {
            secretName = results.get(0);
            System.out.println("\n✔ Secreto encontrado: " + secretName);
        } else {
            // Multiple matches: show the list and allow selection
            System.out.println("\n🔍 Se encontraron " + results.size() + " coincidencias:");
            System.out.println("───────────────────────────────");
            for (int i = 0; i < results.size(); i++) {
                System.out.println((i + 1) + ". " + results.get(i));
            }
            System.out.println("0. Cancelar");
            System.out.println("───────────────────────────────");

            System.out.print("Seleccione un número: ");
            int selection = readOption();

            if (selection == 0) {
                System.out.println("Actualización cancelada.");
                return;
            }

            if (selection < 1 || selection > results.size()) {
                System.out.println("⚠ Selección inválida.");
                return;
            }

            secretName = results.get(selection - 1);
        }

        // Show the current value
        String currentValue = vault.getSecret(secretName);
        System.out.println("Valor actual: " + currentValue);

        // Request confirmation
        Boolean confirmation = readConfirmation("\n¿Desea modificar este secreto? (S/N): ");
        if (confirmation == null) {
            savePendingChanges();
            return;
        }
        if (!confirmation) {
            System.out.println("Actualización cancelada.");
            return;
        }

        // Request the new value
        System.out.print("Nuevo valor del secreto: ");
        String newValue = readLine();

        // Update the secret
        if (isInputEnded()) {
            savePendingChanges();
            return;
        }
        if (newValue.trim().isEmpty()) {
            System.out.println("Error: el valor no puede estar vacío.");
            return;
        }
        try {
            if (vault.updateSecret(secretName, newValue)) {
                dirty = true;
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Error: " + e.getMessage());
        }
    }

    private Boolean readConfirmation(String prompt) {
        while (!isInputEnded()) {
            System.out.print(prompt);
            String answer = readLine().trim();
            if (isInputEnded()) {
                return null;
            }
            if (answer.equalsIgnoreCase("S") || answer.equalsIgnoreCase("Y")) {
                return true;
            }
            if (answer.equalsIgnoreCase("N")) {
                return false;
            }
            System.out.println("Respuesta no válida. Escribe S o N.");
        }
        return null;
    }
}
