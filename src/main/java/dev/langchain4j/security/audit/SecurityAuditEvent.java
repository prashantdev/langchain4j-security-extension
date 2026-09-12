package dev.langchain4j.security.audit;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;

/**
 * Immutable audit event envelope compatible with OCSF and ECS standards.
 */
public record SecurityAuditEvent(
    UUID eventId,
    String schemaVersion,
    Instant timestampUtc,
    String invocationId,
    String traceId,
    String subjectId,
    String tenantId,
    Set<String> subjectRoles,
    int subjectClearance,
    String enforcementPoint,
    String action,
    String targetResource,
    String decision,
    String reasonCode,
    Map<String, Object> payloadSnapshot,
    String severity
) implements Serializable {

    public SecurityAuditEvent {
        if (eventId == null) {
            eventId = UUID.randomUUID();
        }
        if (schemaVersion == null || schemaVersion.isBlank()) {
            schemaVersion = "1.0";
        }
        if (timestampUtc == null) {
            timestampUtc = Instant.now();
        }
        if (subjectRoles == null || subjectRoles.isEmpty()) {
            subjectRoles = Set.of();
        } else {
            subjectRoles = Collections.unmodifiableSet(new HashSet<>(subjectRoles));
        }
        if (payloadSnapshot == null || payloadSnapshot.isEmpty()) {
            payloadSnapshot = Map.of();
        } else {
            payloadSnapshot = Collections.unmodifiableMap(new HashMap<>(payloadSnapshot));
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private UUID eventId;
        private String schemaVersion = "1.0";
        private Instant timestampUtc = Instant.now();
        private String invocationId = "";
        private String traceId = "";
        private String subjectId = "UNKNOWN";
        private String tenantId = "UNKNOWN";
        private Set<String> subjectRoles = Set.of();
        private int subjectClearance = 0;
        private String enforcementPoint = "SECURITY_CORE";
        private String action = "";
        private String targetResource = "";
        private String decision = "ALLOW";
        private String reasonCode = "";
        private Map<String, Object> payloadSnapshot = Map.of();
        private String severity = "INFORMATIONAL";

        public Builder eventId(UUID id) {
            this.eventId = id;
            return this;
        }

        public Builder schemaVersion(String v) {
            this.schemaVersion = v;
            return this;
        }

        public Builder timestampUtc(Instant t) {
            this.timestampUtc = t;
            return this;
        }

        public Builder invocationId(String id) {
            this.invocationId = id;
            return this;
        }

        public Builder traceId(String id) {
            this.traceId = id;
            return this;
        }

        public Builder subjectId(String id) {
            this.subjectId = id;
            return this;
        }

        public Builder tenantId(String id) {
            this.tenantId = id;
            return this;
        }

        public Builder subjectRoles(Set<String> roles) {
            this.subjectRoles = roles;
            return this;
        }

        public Builder subjectClearance(int cl) {
            this.subjectClearance = cl;
            return this;
        }

        public Builder enforcementPoint(String ep) {
            this.enforcementPoint = ep;
            return this;
        }

        public Builder action(String act) {
            this.action = act;
            return this;
        }

        public Builder targetResource(String tr) {
            this.targetResource = tr;
            return this;
        }

        public Builder decision(String dec) {
            this.decision = dec;
            return this;
        }

        public Builder reasonCode(String rc) {
            this.reasonCode = rc;
            return this;
        }

        public Builder payloadSnapshot(Map<String, Object> ps) {
            this.payloadSnapshot = ps;
            return this;
        }

        public Builder severity(String sev) {
            this.severity = sev;
            return this;
        }

        public SecurityAuditEvent build() {
            return new SecurityAuditEvent(
                eventId,
                schemaVersion,
                timestampUtc,
                invocationId,
                traceId,
                subjectId,
                tenantId,
                subjectRoles,
                subjectClearance,
                enforcementPoint,
                action,
                targetResource,
                decision,
                reasonCode,
                payloadSnapshot,
                severity
            );
        }
    }
}
