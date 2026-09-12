package dev.langchain4j.security.context;

import java.util.Optional;
import java.util.function.Supplier;

/**
 * Thread-scoped container for active {@link SecurityIdentity} propagation across execution boundaries.
 * Uses {@link InheritableThreadLocal} to allow downstream worker threads and tool interceptors
 * to inherit the caller identity during AI Service turns.
 */
public final class SecurityContextHolder {

    private static final ThreadLocal<SecurityIdentity> CONTEXT = new InheritableThreadLocal<>();

    private SecurityContextHolder() {
        // Private constructor for utility class
    }

    /**
     * Sets the active security identity for the current thread.
     *
     * @param identity the identity to bind, or null to clear
     */
    public static void setIdentity(SecurityIdentity identity) {
        if (identity == null) {
            CONTEXT.remove();
        } else {
            CONTEXT.set(identity);
        }
    }

    /**
     * Retrieves the active security identity bound to the current thread.
     *
     * @return an {@link Optional} containing the bound security identity, or empty if unbound
     */
    public static Optional<SecurityIdentity> getIdentity() {
        return Optional.ofNullable(CONTEXT.get());
    }

    /**
     * Clears the security context from the current thread.
     */
    public static void clear() {
        CONTEXT.remove();
    }

    /**
     * Executes a supplier task within the scope of a specified security identity,
     * ensuring context is restored/cleared after completion.
     *
     * @param identity the security identity to bind during task execution
     * @param task the supplier task to execute
     * @param <T> the return type of the task
     * @return the result of the task execution
     */
    public static <T> T runWithIdentity(SecurityIdentity identity, Supplier<T> task) {
        SecurityIdentity previous = CONTEXT.get();
        try {
            setIdentity(identity);
            return task.get();
        } finally {
            setIdentity(previous);
        }
    }

    /**
     * Executes a runnable task within the scope of a specified security identity,
     * ensuring context is restored/cleared after completion.
     *
     * @param identity the security identity to bind during task execution
     * @param task the runnable task to execute
     */
    public static void runWithIdentity(SecurityIdentity identity, Runnable task) {
        SecurityIdentity previous = CONTEXT.get();
        try {
            setIdentity(identity);
            task.run();
        } finally {
            setIdentity(previous);
        }
    }
}
