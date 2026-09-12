package dev.langchain4j.security.audit;

import java.io.Closeable;

/**
 * Service Provider Interface for publishing security audit events.
 */
public interface SecurityAuditPublisher extends Closeable {

    /**
     * Publishes a security audit event.
     *
     * @param event the audit event to record
     */
    void publish(SecurityAuditEvent event);

    /**
     * Flushes any buffered events to the underlying sink.
     */
    default void flush() {}

    @Override
    default void close() {}

    /**
     * Creates a no-op publisher that ignores all emitted events.
     *
     * @return a no-op publisher instance
     */
    static SecurityAuditPublisher noop() {
        return event -> {};
    }
}
