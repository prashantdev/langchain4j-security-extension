package dev.langchain4j.security.audit;

import java.io.Serializable;
import java.time.Instant;
import java.util.*;

/**
 * Immutable audit event envelope compatible with OCSF and ECS standards.
 *
 * @param eventId unique event identifier
 * @param schemaVersion event schema version
 * @param timestampUtc timestamp of event creation in UTC
 * @param invocationId optional invocation identifier
 * @param traceId optional distributed trace identifier
 * @param subjectId subject identifier
 * @param tenantId tenant identifier
 * @param subjectRoles set of subject roles
 * @param subjectClearance clearance rank of subject
 * @param enforcementPoint point of security enforcement
 * @param action security action performed
 * @param targetResource target resource being accessed
 * @param decision policy decision (e.g. ALLOW, DENY)
 * @param reasonCode reason code explaining decision
 * @param payloadSnapshot optional snapshot of payload data
 * @param severity audit event severity
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

    /**
     * Compact constructor validating and providing default fallback values for SecurityAuditEvent.
     *
     * @param eventId unique event identifier
     * @param schemaVersion event schema version
     * @param timestampUtc timestamp of event creation in UTC
     * @param invocationId optional invocation identifier
     * @param traceId optional distributed trace identifier
     * @param subjectId subject identifier
     * @param tenantId tenant identifier
     * @param subjectRoles set of subject roles
     * @param subjectClearance clearance rank of subject
     * @param enforcementPoint point of security enforcement
     * @param action security action performed
     * @param targetResource target resource being accessed
     * @param decision policy decision (e.g. ALLOW, DENY)
     * @param reasonCode reason code explaining decision
     * @param payloadSnapshot optional snapshot of payload data
     * @param severity audit event severity
     */
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

    /**
     * Returns a new Builder for constructing a {@link SecurityAuditEvent}.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for constructing immutable {@link SecurityAuditEvent} instances.
     */
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

        /**
         * Sets the event ID.
         * @param id event UUID
         * @return this Builder
         */
        public Builder eventId(UUID id) {
            this.eventId = id;
            return this;
        }

        /**
         * Sets the schema version.
         * @param v schema version string
         * @return this Builder
         */
        public Builder schemaVersion(String v) {
            this.schemaVersion = v;
            return this;
        }

        /**
         * Sets the UTC timestamp.
         * @param t timestamp Instant
         * @return this Builder
         */
        public Builder timestampUtc(Instant t) {
            this.timestampUtc = t;
            return this;
        }

        /**
         * Sets the invocation ID.
         * @param id invocation ID string
         * @return this Builder
         */
        public Builder invocationId(String id) {
            this.invocationId = id;
            return this;
        }

        /**
         * Sets the trace ID.
         * @param id trace ID string
         * @return this Builder
         */
        public Builder traceId(String id) {
            this.traceId = id;
            return this;
        }

        /**
         * Sets the subject ID.
         * @param id subject ID string
         * @return this Builder
         */
        public Builder subjectId(String id) {
            this.subjectId = id;
            return this;
        }

        /**
         * Sets the tenant ID.
         * @param id tenant ID string
         * @return this Builder
         */
        public Builder tenantId(String id) {
            this.tenantId = id;
            return this;
        }

        /**
         * Sets the subject roles.
         * @param roles set of role names
         * @return this Builder
         */
        public Builder subjectRoles(Set<String> roles) {
            this.subjectRoles = roles;
            return this;
        }

        /**
         * Sets the subject clearance.
         * @param cl clearance level
         * @return this Builder
         */
        public Builder subjectClearance(int cl) {
            this.subjectClearance = cl;
            return this;
        }

        /**
         * Sets the enforcement point name.
         * @param ep enforcement point string
         * @return this Builder
         */
        public Builder enforcementPoint(String ep) {
            this.enforcementPoint = ep;
            return this;
        }

        /**
         * Sets the security action.
         * @param act action name
         * @return this Builder
         */
        public Builder action(String act) {
            this.action = act;
            return this;
        }

        /**
         * Sets the target resource.
         * @param tr target resource identifier
         * @return this Builder
         */
        public Builder targetResource(String tr) {
            this.targetResource = tr;
            return this;
        }

        /**
         * Sets the policy decision.
         * @param dec decision string
         * @return this Builder
         */
        public Builder decision(String dec) {
            this.decision = dec;
            return this;
        }

        /**
         * Sets the reason code.
         * @param rc reason code string
         * @return this Builder
         */
        public Builder reasonCode(String rc) {
            this.reasonCode = rc;
            return this;
        }

        /**
         * Sets the payload snapshot.
         * @param ps payload map
         * @return this Builder
         */
        public Builder payloadSnapshot(Map<String, Object> ps) {
            this.payloadSnapshot = ps;
            return this;
        }

        /**
         * Sets the event severity.
         * @param sev severity level string
         * @return this Builder
         */
        public Builder severity(String sev) {
            this.severity = sev;
            return this;
        }

        /**
         * Builds a new {@link SecurityAuditEvent} instance.
         * @return a new SecurityAuditEvent
         */
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
