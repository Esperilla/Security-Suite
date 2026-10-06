package main;

import models.Vault;
import models.VaultStorage;
import models.AuditLog;
import models.EncryptionUtils;
import modules.BaseModule;
import modules.FileModule;
import modules.VaultModule;
import java.io.Console;

public class Main {

    // Console for ALL user input (avoids buffer issues)
    private static final Console console = System.console();
    // Vault storage used to save and load the vault
    private static final VaultStorage storage = new VaultStorage();
    // Current vault in memory
    private static Vault vault;
    // Current master password
    private static String currentPassword;


    // --- Main method ---
    public static void main(String[] args) {
        // Verify that Console is available (only works in a real terminal)
        if (console == null) {
            AuditLog.error("Programa ejecutado sin consola real.");
            System.err.println("Error: Este programa debe ejecutarse desde una terminal/consola real.");
            System.err.println("No se puede ejecutar desde un IDE. Use: java -cp <classpath> main.Main");
            System.exit(1);
        }

        System.out.println("--- SUITE DE SEGURIDAD (JAVA POO) ---");

        try {
            // Login (whether a vault exists or not)
            if (storage.vaultExists()) {
                logIn();
            } else {
                createNewVault();
            }

            // POLYMORPHISM: use the parent class (BaseModule) to refer to child classes
            // Note: vaultModule is concrete to access getPassword()
            VaultModule vaultModule = new VaultModule(vault, storage, currentPassword, console);
            BaseModule fileModule = new FileModule(currentPassword, console);

            // Main menu
            boolean running = true;

            while (running) {
                System.out.println("\n--- Menú Principal ---");
                System.out.println("1. " + vaultModule.getName());
                System.out.println("2. " + fileModule.getName());
                System.out.println("3. Salir");

                String option = console.readLine("> ");
                if (option == null) {
                    option = "3";
                } else {
                    option = option.trim();
                }

                switch (option) {
                    case "1":
                        vaultModule.execute();
                        // Check whether the password changed during execution
                        if (!currentPassword.equals(vaultModule.getPassword())) {
                            currentPassword = vaultModule.getPassword();
                            // Recreate the file module with the new password
                            fileModule = new FileModule(currentPassword, console);
                            System.out.println("(El Cifrador de Archivos ahora usa la nueva contraseña)");
                        }
                        break;
                    case "2":
                        fileModule.execute();
                        break;
                    case "3":
                        vaultModule.savePendingChanges();
                        AuditLog.info("Aplicación cerrada por el usuario");
                        System.out.println("Cerrando programa... ¡Adiós!");
                        running = false;
                        break;
                    default:
                        System.out.println("Opción no válida.");
                }
            }

        } catch (Exception e) {
            AuditLog.error("Error Fatal: " + e.getMessage());
            System.err.println("Error fatal: " + e.getMessage());
        }
    }

    // --- Login methods ---

    private static void createNewVault() throws Exception {
        System.out.println("\n--- Configuración Inicial ---");
        System.out.println("Bienvenido. Crea una contraseña maestra.");
        System.out.println();
        System.out.println(EncryptionUtils.PASSWORD_REQUIREMENTS);
        System.out.println();

        String newPassword;
        String validationError;

        // Loop until the password complies with the policy
        do {
            newPassword = readPassword("Nueva contraseña: ");
            if (newPassword == null) {
                throw new Exception("Entrada finalizada.");
            }
            validationError = EncryptionUtils.validatePasswordPolicy(newPassword);

            if (validationError != null) {
                System.out.println("\n⚠ " + validationError);
                System.out.println("Intenta de nuevo.\n");
            }
        } while (validationError != null);

        String confirmedPassword;
        do {
            confirmedPassword = readPassword("Confirma contraseña: ");
            if (confirmedPassword == null) {
                throw new Exception("Entrada finalizada.");
            }
            if (!newPassword.equals(confirmedPassword)) {
                AuditLog.warn("Confirmación de contraseña inicial no coincidente.");
                System.out.println("\n⚠ Las contraseñas no coinciden. Confírmala de nuevo.\n");
            }
        } while (!newPassword.equals(confirmedPassword));

        if (confirmedPassword.isEmpty()) {
            throw new Exception("La contraseña no puede estar vacía.");
        }

        currentPassword = newPassword;
        vault = new Vault();
        storage.saveVault(vault, currentPassword);
        AuditLog.info("Nueva bóveda creada exitosamente. ");
        System.out.println("¡Sistema configurado correctamente!");
    }

    private static void logIn() throws Exception {
        System.out.println("\n--- Inicio de Sesión ---");
        for (int attempt = 1; attempt <= 3; attempt++) {
            String storedPassword = readPassword("Introduce tu contraseña maestra: ");
            if (storedPassword == null) {
                throw new Exception("Entrada finalizada.");
            }
            try {
                if (storedPassword.trim().isEmpty()) {
                    throw new Exception("La contraseña no puede estar vacía.");
                }
                vault = storage.loadVault(storedPassword);
                currentPassword = storedPassword;
                AuditLog.info("Inicio de sesión exitoso");
                System.out.println("¡Acceso concedido!");
                return;
            } catch (Exception e) {
                int remaining = 3 - attempt;
                if (remaining == 0) {
                    AuditLog.warn("Se agotaron los intentos de inicio de sesión.");
                    throw new Exception("Demasiados intentos fallidos.", e);
                }
                AuditLog.warn("Intento de inicio de sesión fallido. Intentos restantes: " + remaining);
                System.out.println("Contraseña incorrecta o bóveda dañada. Intentos restantes: " + remaining);
            }
        }
    }

    // Reads a password while hiding the input
    private static String readPassword(String prompt) {
        if (console == null) {
            return null;
        }
        char[] passwordArray = console.readPassword(prompt);
        if (passwordArray == null) {
            return null;
        }
        if (passwordArray.length == 0) {
            return "";
        }
        String result = new String(passwordArray);
        // Clear the array for security
        java.util.Arrays.fill(passwordArray, '\0');
        return result;
    }
}
