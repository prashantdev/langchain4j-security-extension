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

    @Test
    @DisplayName("Should serialize SecurityAuditEvent to standard single-line JSON with all OCSF/ECS fields")
    void testSerializationFields() throws Exception {
        Slf4jJsonAuditPublisher publisher = new Slf4jJsonAuditPublisher();
        ObjectMapper mapper = publisher.getObjectMapper();

        UUID eventId = UUID.randomUUID();
        SecurityAuditEvent event = SecurityAuditEvent.builder()
            .eventId(eventId)
            .schemaVersion("1.0")
            .invocationId("inv-99")
            .traceId("trace-123")
            .subjectId("alice")
            .tenantId("TENANT_CORP")
            .subjectRoles(Set.of("SECURITY_ADMIN", "AUDITOR"))
            .subjectClearance(2)
            .enforcementPoint("AGENT_GUARD")
            .action("agent:invoke")
            .targetResource("CustomerSupportAgent#chat")
            .decision("ALLOW")
            .reasonCode("AGENT_ACCESS_PERMITTED")
            .payloadSnapshot(Map.of("sessionId", "s-1"))
            .severity("INFORMATIONAL")
            .build();

        String json = mapper.writeValueAsString(event);
        assertThat(json).doesNotContain("\n"); // Single line

        JsonNode root = mapper.readTree(json);
        assertThat(root.get("eventId").asText()).isEqualTo(eventId.toString());
        assertThat(root.get("schemaVersion").asText()).isEqualTo("1.0");
        assertThat(root.get("subjectId").asText()).isEqualTo("alice");
        assertThat(root.get("tenantId").asText()).isEqualTo("TENANT_CORP");
        assertThat(root.get("subjectClearance").asInt()).isEqualTo(2);
        assertThat(root.get("decision").asText()).isEqualTo("ALLOW");
        assertThat(root.get("reasonCode").asText()).isEqualTo("AGENT_ACCESS_PERMITTED");
        assertThat(root.get("enforcementPoint").asText()).isEqualTo("AGENT_GUARD");
        assertThat(root.get("payloadSnapshot").get("sessionId").asText()).isEqualTo("s-1");
    }

    @Test
    @DisplayName("Should execute publish across all severity levels without throwing exceptions")
    void testPublishSeverityLevels() {
        Slf4jJsonAuditPublisher publisher = new Slf4jJsonAuditPublisher();

        SecurityAuditEvent infoEvent = SecurityAuditEvent.builder()
            .severity("INFORMATIONAL")
            .subjectId("user1")
            .build();
        publisher.publish(infoEvent);

        SecurityAuditEvent warnEvent = SecurityAuditEvent.builder()
            .severity("WARNING")
            .subjectId("user2")
            .build();
        publisher.publish(warnEvent);

        SecurityAuditEvent alertEvent = SecurityAuditEvent.builder()
            .severity("SECURITY_ALERT")
            .subjectId("user3")
            .build();
        publisher.publish(alertEvent);

        SecurityAuditEvent criticalEvent = SecurityAuditEvent.builder()
            .severity("CRITICAL_ALERT")
            .subjectId("user4")
            .build();
        publisher.publish(criticalEvent);

        // Null event should be ignored safely
        publisher.publish(null);
    }
}
