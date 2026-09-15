package dev.langchain4j.security.audit.slf4j;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serializes {@link SecurityAuditEvent} records into single-line JSON records
 * emitted to logger 'audit.security.langchain4j'.
 */
public class Slf4jJsonAuditPublisher implements SecurityAuditPublisher {

    public static final String LOGGER_NAME = "audit.security.langchain4j";
    private static final Logger log = LoggerFactory.getLogger(LOGGER_NAME);
    private final ObjectMapper mapper;

    public Slf4jJsonAuditPublisher() {
        this.mapper = new ObjectMapper();
        this.mapper.registerModule(new JavaTimeModule());
        this.mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    private ObjectMapper getObjectMapper() {
        return mapper;
    }

    @Override
    public void publish(SecurityAuditEvent event) {
        if (event == null) {
            return;
        }
        try {
            String json = mapper.writeValueAsString(event);
            String sev = event.severity() == null ? "INFORMATIONAL" : event.severity().toUpperCase();
            switch (sev) {
                case "CRITICAL_ALERT", "SECURITY_ALERT" -> log.error(json);
                case "WARNING" -> log.warn(json);
                default -> log.info(json);
            }
        } catch (Exception e) {
            log.error("{\"error\": \"AUDIT_SERIALIZATION_FAILED\", \"message\": \"{}\"}", e.getMessage());
        }
    }
}
