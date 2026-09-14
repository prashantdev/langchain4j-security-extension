package dev.langchain4j.security.audit.slf4j;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class Slf4jJsonAuditPublisherTest {

    private static final String SCHEMA_VERSION_1_0 = "1.0";
    private static final String SUBJECT_ALICE = "alice";
    private static final String TENANT_CORP = "TENANT_CORP";
    private static final String ENFORCEMENT_POINT_AGENT_GUARD = "AGENT_GUARD";
    private static final String DECISION_ALLOW = "ALLOW";
    private static final String REASON_AGENT_ACCESS_PERMITTED = "AGENT_ACCESS_PERMITTED";

    private static final String SEVERITY_INFORMATIONAL = "INFORMATIONAL";
    private static final String SEVERITY_WARNING = "WARNING";
    private static final String SEVERITY_SECURITY_ALERT = "SECURITY_ALERT";
    private static final String SEVERITY_CRITICAL_ALERT = "CRITICAL_ALERT";

    private SecurityAuditEvent createTestEvent(String subjectId, String severity) {
        return SecurityAuditEvent.builder()
            .severity(severity)
            .subjectId(subjectId)
            .build();
    }

    @Test
    @DisplayName("Should serialize SecurityAuditEvent to standard single-line JSON with all OCSF/ECS fields")
    void testSerializationFields() throws Exception {
        Slf4jJsonAuditPublisher publisher = new Slf4jJsonAuditPublisher();
        ObjectMapper mapper = publisher.getObjectMapper();

        UUID eventId = UUID.randomUUID();
        SecurityAuditEvent event = SecurityAuditEvent.builder()
            .eventId(eventId)
            .schemaVersion(SCHEMA_VERSION_1_0)
            .invocationId("inv-99")
            .traceId("trace-123")
            .subjectId(SUBJECT_ALICE)
            .tenantId(TENANT_CORP)
            .subjectRoles(Set.of("SECURITY_ADMIN", "AUDITOR"))
            .subjectClearance(2)
            .enforcementPoint(ENFORCEMENT_POINT_AGENT_GUARD)
            .action("agent:invoke")
            .targetResource("CustomerSupportAgent#chat")
            .decision(DECISION_ALLOW)
            .reasonCode(REASON_AGENT_ACCESS_PERMITTED)
            .payloadSnapshot(Map.of("sessionId", "s-1"))
            .severity(SEVERITY_INFORMATIONAL)
            .build();

        String json = mapper.writeValueAsString(event);
        assertThat(json).doesNotContain("\n"); // Single line

        JsonNode root = mapper.readTree(json);
        assertThat(root.get("eventId").asText()).isEqualTo(eventId.toString());
        assertThat(root.get("schemaVersion").asText()).isEqualTo(SCHEMA_VERSION_1_0);
        assertThat(root.get("subjectId").asText()).isEqualTo(SUBJECT_ALICE);
        assertThat(root.get("tenantId").asText()).isEqualTo(TENANT_CORP);
        assertThat(root.get("subjectClearance").asInt()).isEqualTo(2);
        assertThat(root.get("decision").asText()).isEqualTo(DECISION_ALLOW);
        assertThat(root.get("reasonCode").asText()).isEqualTo(REASON_AGENT_ACCESS_PERMITTED);
        assertThat(root.get("enforcementPoint").asText()).isEqualTo(ENFORCEMENT_POINT_AGENT_GUARD);
        assertThat(root.get("payloadSnapshot").get("sessionId").asText()).isEqualTo("s-1");
    }

    @Test
    @DisplayName("Should execute publish across all severity levels without throwing exceptions")
    void testPublishSeverityLevels() {
        Slf4jJsonAuditPublisher publisher = new Slf4jJsonAuditPublisher();

        publisher.publish(createTestEvent("user1", SEVERITY_INFORMATIONAL));
        publisher.publish(createTestEvent("user2", SEVERITY_WARNING));
        publisher.publish(createTestEvent("user3", SEVERITY_SECURITY_ALERT));
        publisher.publish(createTestEvent("user4", SEVERITY_CRITICAL_ALERT));

        // Null event should be ignored safely
        publisher.publish(null);
    }
}

