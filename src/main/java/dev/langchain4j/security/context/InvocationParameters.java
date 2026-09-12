package dev.langchain4j.security.context;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Immutable parameters container representing in-band context across model and tool execution lifecycles.
 */
public final class InvocationParameters implements Serializable {

    private final Map<String, Object> parameters;

    private InvocationParameters(Map<String, Object> parameters) {
        if (parameters == null || parameters.isEmpty()) {
            this.parameters = Map.of();
        } else {
            Map<String, Object> clean = new HashMap<>();
            for (Map.Entry<String, Object> entry : parameters.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    clean.put(entry.getKey(), entry.getValue());
                }
            }
            this.parameters = Collections.unmodifiableMap(clean);
        }
    }

    public static InvocationParameters empty() {
        return new InvocationParameters(Map.of());
    }

    public static InvocationParameters from(Map<String, Object> map) {
        return new InvocationParameters(map);
    }

    public boolean containsKey(String key) {
        if (key == null) {
            return false;
        }
        return parameters.containsKey(key);
    }

    public Optional<Object> get(String key) {
        if (key == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(parameters.get(key));
    }

    public <T> Optional<T> get(String key, Class<T> type) {
        if (key == null || type == null) {
            return Optional.empty();
        }
        Object val = parameters.get(key);
        if (val != null && type.isInstance(val)) {
            return Optional.of(type.cast(val));
        }
        return Optional.empty();
    }

    public Map<String, Object> asMap() {
        return parameters;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InvocationParameters that = (InvocationParameters) o;
        return Objects.equals(parameters, that.parameters);
    }

    @Override
    public int hashCode() {
        return Objects.hash(parameters);
    }

    @Override
    public String toString() {
        return "InvocationParameters{" +
            "parameters=" + parameters +
            '}';
    }
}
