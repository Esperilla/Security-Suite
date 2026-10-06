package modules;

import java.io.Console;

public abstract class BaseModule {

    // Use Console instead of Scanner to avoid buffer issues
    protected Console console;
    private boolean inputEnded;

    // Constructor: receives and stores Main's Console
    public BaseModule(Console console) {
        this.console = console;
    }

    // Utility method for reading numbers
    protected int readOption() {
        if (inputEnded) {
            return -1;
        }
        try {
            String linea = readLine().trim();
            return Integer.parseInt(linea);
        } catch (NumberFormatException | NullPointerException e) {
            return -1; // Invalid option
        }
    }

    // Utility method for reading text
    protected String readLine() {
        if (console == null) {
            inputEnded = true;
            return "";
        }
        String line = console.readLine();
        if (line == null) {
            inputEnded = true;
            return "";
        }
        return line;
    }

    protected boolean isInputEnded() {
        return inputEnded;
    }

    protected void markInputEnded() {
        inputEnded = true;
    }

    public final boolean hasInputEnded() {
        return inputEnded;
    }

    // --- ABSTRACT METHODS (Polymorphism) ---

    public abstract void execute() throws Exception;

    public abstract String getName();
}
