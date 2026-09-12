package dev.langchain4j.security.pdp;

import dev.langchain4j.security.context.SecurityIdentity;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Normalized policy evaluation request envelope.
 */
public record PolicyEvaluationRequest(
    SecurityIdentity subject,
    String action,
    String resource,
    Map<String, Object> context
) {
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

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private SecurityIdentity subject;
        private String action;
        private String resource;
        private Map<String, Object> context = new HashMap<>();

        public Builder subject(SecurityIdentity subject) {
            this.subject = subject;
            return this;
        }

        public Builder action(String action) {
            this.action = action;
            return this;
        }

        public Builder resource(String resource) {
            this.resource = resource;
            return this;
        }

        public Builder context(Map<String, Object> context) {
            this.context = (context == null) ? new HashMap<>() : new HashMap<>(context);
            return this;
        }

        public Builder addContext(String key, Object value) {
            if (key != null && value != null) {
                this.context.put(key, value);
            }
            return this;
        }

        public PolicyEvaluationRequest build() {
            return new PolicyEvaluationRequest(subject, action, resource, context);
        }
    }
}
