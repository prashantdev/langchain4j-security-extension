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
 *
 * @param subjectId subject unique identifier
 * @param tenantId tenant unique identifier
 * @param roles set of role names assigned to subject
 * @param clearanceFloor clearance floor rank
 * @param departmentId optional department identifier
 * @param attributes optional custom attributes map
 */
public record SecurityIdentity(
    String subjectId,
    String tenantId,
    Set<String> roles,
    int clearanceFloor,
    String departmentId,
    Map<String, Object> attributes
) implements Serializable {

    /** Constant representing anonymous subject ID. */
    public static final String ANONYMOUS_SUBJECT = "anonymous";

    /** Default clearance floor rank constant (0). */
    public static final int DEFAULT_CLEARANCE = 0;

    /**
     * Returns the subject unique identifier.
     *
     * @return subject ID string
     */
    @Override
    public String subjectId() {
        return subjectId;
    }

    /**
     * Returns the tenant unique identifier.
     *
     * @return tenant ID string
     */
    @Override
    public String tenantId() {
        return tenantId;
    }

    /**
     * Returns the set of role names assigned to subject.
     *
     * @return set of role names
     */
    @Override
    public Set<String> roles() {
        return roles;
    }

    /**
     * Returns the clearance floor rank.
     *
     * @return clearance floor level
     */
    @Override
    public int clearanceFloor() {
        return clearanceFloor;
    }

    /**
     * Returns the optional department identifier.
     *
     * @return department ID string, or null
     */
    @Override
    public String departmentId() {
        return departmentId;
    }

    /**
     * Returns the optional custom attributes map.
     *
     * @return map of custom attributes
     */
    @Override
    public Map<String, Object> attributes() {
        return attributes;
    }

    /**
     * Compact constructor validating required fields and creating unmodifiable sets and maps for SecurityIdentity.
     *
     * @param subjectId subject unique identifier
     * @param tenantId tenant unique identifier
     * @param roles set of role names assigned to subject
     * @param clearanceFloor clearance floor rank
     * @param departmentId optional department identifier
     * @param attributes optional custom attributes map
     */
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

    /**
     * Checks if this identity has the specified role.
     *
     * @param role role name
     * @return true if identity possesses role, false otherwise
     */
    public boolean hasRole(String role) {
        return role != null && roles.contains(role);
    }

    /**
     * Evaluates if this identity's clearance floor satisfies the required clearance rank.
     *
     * @param requiredClearance required clearance rank
     * @return true if clearanceFloor >= requiredClearance, false otherwise
     */
    public boolean satisfiesClearance(int requiredClearance) {
        return this.clearanceFloor >= requiredClearance;
    }

    /**
     * Gets a custom attribute by key.
     *
     * @param key attribute key
     * @return Optional attribute value if present
     */
    public Optional<Object> getAttribute(String key) {
        if (key == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(attributes.get(key));
    }

    /**
     * Gets a typed custom attribute by key.
     *
     * @param <T> attribute type
     * @param key attribute key
     * @param type target class type
     * @return Optional containing typed attribute value if present and matching type
     */
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

    /**
     * Creates a new Builder for constructing a {@link SecurityIdentity}.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates an anonymous {@link SecurityIdentity} for the given tenant ID.
     *
     * @param tenantId tenant identifier
     * @return anonymous SecurityIdentity
     */
    public static SecurityIdentity anonymous(String tenantId) {
        return builder()
            .subjectId(ANONYMOUS_SUBJECT)
            .tenantId(tenantId)
            .clearanceFloor(DEFAULT_CLEARANCE)
            .roles(Set.of("ANONYMOUS"))
            .build();
    }

    /**
     * Builder for constructing immutable {@link SecurityIdentity} instances.
     */
    public static class Builder {
        private String subjectId;
        private String tenantId;
        private Set<String> roles = new HashSet<>();
        private int clearanceFloor = DEFAULT_CLEARANCE;
        private String departmentId;
        private Map<String, Object> attributes = new HashMap<>();

        /**
         * Sets the subject ID.
         * @param subjectId subject unique identifier
         * @return this Builder
         */
        public Builder subjectId(String subjectId) {
            this.subjectId = subjectId;
            return this;
        }

        /**
         * Sets the tenant ID.
         * @param tenantId tenant unique identifier
         * @return this Builder
         */
        public Builder tenantId(String tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        /**
         * Sets the assigned roles set.
         * @param roles set of role names
         * @return this Builder
         */
        public Builder roles(Set<String> roles) {
            this.roles = (roles == null) ? new HashSet<>() : new HashSet<>(roles);
            return this;
        }

        /**
         * Adds a single role name.
         * @param role role name
         * @return this Builder
         */
        public Builder addRole(String role) {
            if (role != null && !role.isBlank()) {
                this.roles.add(role.trim());
            }
            return this;
        }

        /**
         * Sets the clearance floor level.
         * @param clearanceFloor clearance rank
         * @return this Builder
         */
        public Builder clearanceFloor(int clearanceFloor) {
            this.clearanceFloor = clearanceFloor;
            return this;
        }

        /**
         * Sets the department ID.
         * @param departmentId department identifier
         * @return this Builder
         */
        public Builder departmentId(String departmentId) {
            this.departmentId = departmentId;
            return this;
        }

        /**
         * Sets custom context attributes map.
         * @param attributes map of custom attributes
         * @return this Builder
         */
        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = (attributes == null) ? new HashMap<>() : new HashMap<>(attributes);
            return this;
        }

        /**
         * Adds a single custom attribute key-value pair.
         * @param key attribute key
         * @param value attribute value
         * @return this Builder
         */
        public Builder addAttribute(String key, Object value) {
            if (key != null && value != null) {
                this.attributes.put(key, value);
            }
            return this;
        }

        /**
         * Builds a new {@link SecurityIdentity} instance.
         * @return a new SecurityIdentity
         */
        public SecurityIdentity build() {
            return new SecurityIdentity(subjectId, tenantId, roles, clearanceFloor, departmentId, attributes);
        }
    }
}
