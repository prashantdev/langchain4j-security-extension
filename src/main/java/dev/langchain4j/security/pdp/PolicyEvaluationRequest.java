package dev.langchain4j.security.pdp;

import dev.langchain4j.security.context.SecurityIdentity;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Normalized policy evaluation request envelope.
 *
 * @param subject security identity of caller
 * @param action security action string
 * @param resource target resource string
 * @param context contextual evaluation parameters
 */
public record PolicyEvaluationRequest(
    /** Security identity of caller. */
    SecurityIdentity subject,
    /** Security action string. */
    String action,
    /** Target resource string. */
    String resource,
    /** Contextual evaluation parameters. */
    Map<String, Object> context
) {
    /**
     * Compact constructor validating and providing default fallback values for PolicyEvaluationRequest.
     *
     * @param subject security identity of caller
     * @param action security action string
     * @param resource target resource string
     * @param context contextual evaluation parameters
     */
    public PolicyEvaluationRequest {
        Objects.requireNonNull(action, "action must not be null");
        Objects.requireNonNull(resource, "resource must not be null");
        if (context == null || context.isEmpty()) {
            context = Map.of();
        } else {
            Map<String, Object> copy = new HashMap<>();
            for (Map.Entry<String, Object> entry : context.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    copy.put(entry.getKey(), entry.getValue());
                }
            }
            context = Collections.unmodifiableMap(copy);
        }
    }

    /**
     * Returns a new Builder for constructing a {@link PolicyEvaluationRequest}.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for constructing immutable {@link PolicyEvaluationRequest} instances.
     */
    public static class Builder {
        private SecurityIdentity subject;
        private String action;
        private String resource;
        private Map<String, Object> context = new HashMap<>();

        /**
         * Sets the caller security identity.
         * @param subject SecurityIdentity
         * @return this Builder
         */
        public Builder subject(SecurityIdentity subject) {
            this.subject = subject;
            return this;
        }

        /**
         * Sets the action identifier.
         * @param action action string
         * @return this Builder
         */
        public Builder action(String action) {
            this.action = action;
            return this;
        }

        /**
         * Sets the target resource identifier.
         * @param resource resource string
         * @return this Builder
         */
        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }

        /**
         * Sets the context parameters map.
         * @param context context map
         * @return this Builder
         */
        public Builder context(Map<String, Object> context) {
            this.context = (context == null) ? new HashMap<>() : new HashMap<>(context);
            return this;
        }

        /**
         * Adds a key-value context parameter.
         * @param key parameter key
         * @param value parameter value
         * @return this Builder
         */
        public Builder addContext(String key, Object value) {
            if (key != null && value != null) {
                this.context.put(key, value);
            }
            return this;
        }

        /**
         * Builds a new {@link PolicyEvaluationRequest}.
         * @return a new PolicyEvaluationRequest
         */
        public PolicyEvaluationRequest build() {
            return new PolicyEvaluationRequest(subject, action, resource, context);
        }
    }
}
