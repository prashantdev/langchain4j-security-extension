package dev.langchain4j.security.context;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable security identity record carrying caller entitlements and context attributes.
 */
public record SecurityIdentity(
    String subjectId,
    String tenantId,
    Set<String> roles,
    int clearanceFloor,
    String departmentId,
    Map<String, Object> attributes
) implements Serializable {

    public static final String ANONYMOUS_SUBJECT = "anonymous";
    public static final int DEFAULT_CLEARANCE = 0;

    public SecurityIdentity {
        if (subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("subjectId must not be null or blank");
        }
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be null or blank");
        }

        if (roles == null || roles.isEmpty()) {
            roles = Set.of();
        } else {
            Set<String> cleanRoles = new HashSet<>();
            for (String role : roles) {
                if (role != null && !role.isBlank()) {
                    cleanRoles.add(role.trim());
                }
            }
            roles = Collections.unmodifiableSet(cleanRoles);
        }

        if (attributes == null || attributes.isEmpty()) {
            attributes = Map.of();
        } else {
            Map<String, Object> cleanAttributes = new HashMap<>();
            for (Map.Entry<String, Object> entry : attributes.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    cleanAttributes.put(entry.getKey(), entry.getValue());
                }
            }
            attributes = Collections.unmodifiableMap(cleanAttributes);
        }
    }

    public boolean hasRole(String role) {
        return role != null && roles.contains(role);
    }

    public boolean satisfiesClearance(int requiredClearance) {
        return this.clearanceFloor >= requiredClearance;
    }

    public Optional<Object> getAttribute(String key) {
        if (key == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(attributes.get(key));
    }

    public <T> Optional<T> getAttribute(String key, Class<T> type) {
        if (key == null || type == null) {
            return Optional.empty();
        }
        Object value = attributes.get(key);
        if (value != null && type.isInstance(value)) {
            return Optional.of(type.cast(value));
        }
        return Optional.empty();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static SecurityIdentity anonymous(String tenantId) {
        return builder()
            .subjectId(ANONYMOUS_SUBJECT)
            .tenantId(tenantId)
            .clearanceFloor(DEFAULT_CLEARANCE)
            .roles(Set.of("ANONYMOUS"))
            .build();
    }

    public static class Builder {
        private String subjectId;
        private String tenantId;
        private Set<String> roles = new HashSet<>();
        private int clearanceFloor = DEFAULT_CLEARANCE;
        private String departmentId;
        private Map<String, Object> attributes = new HashMap<>();

        public Builder subjectId(String subjectId) {
            this.subjectId = subjectId;
            return this;
        }

        public Builder tenantId(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder roles(Set<String> roles) {
            this.roles = (roles == null) ? new HashSet<>() : new HashSet<>(roles);
            return this;
        }

        public Builder addRole(String role) {
            if (role != null && !role.isBlank()) {
                this.roles.add(role.trim());
            }
            return this;
        }

        public Builder clearanceFloor(int clearanceFloor) {
            this.clearanceFloor = clearanceFloor;
            return this;
        }

        public Builder departmentId(String departmentId) {
            this.departmentId = departmentId;
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = (attributes == null) ? new HashMap<>() : new HashMap<>(attributes);
            return this;
        }

        public Builder addAttribute(String key, Object value) {
            if (key != null && value != null) {
                this.attributes.put(key, value);
            }
            return this;
        }

        public SecurityIdentity build() {
            return new SecurityIdentity(subjectId, tenantId, roles, clearanceFloor, departmentId, attributes);
        }
    }
}
