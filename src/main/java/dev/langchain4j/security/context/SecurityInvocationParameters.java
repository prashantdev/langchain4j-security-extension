package dev.langchain4j.security.context;

import dev.langchain4j.rag.query.Query;

import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Utility class providing constant keys and helper methods for packing, extracting,
 * and propagating security context within {@link InvocationParameters}.
 */
public final class SecurityInvocationParameters {

    /** Security context parameter key for full SecurityIdentity object. */
    public static final String KEY_IDENTITY = "sec:identity";

    /** Security context parameter key for tenant ID string. */
    public static final String KEY_TENANT_ID = "sec:tenant_id";

    /** Security context parameter key for subject ID string. */
    public static final String KEY_SUBJECT_ID = "sec:subject_id";

    /** Security context parameter key for roles collection. */
    public static final String KEY_ROLES = "sec:roles";

    /** Security context parameter key for clearance floor rank integer. */
    public static final String KEY_CLEARANCE_FLOOR = "sec:clearance_floor";

    /** Security context parameter key for department ID string. */
    public static final String KEY_DEPARTMENT_ID = "sec:department_id";

    private SecurityInvocationParameters() {
        // Utility class
    }

    /**
     * Injects a {@link SecurityIdentity} into existing invocation parameters,
     * serializing both the composite identity object and individual context keys.
     *
     * @param existing the existing parameters, may be null
     * @param identity the security identity to inject, must not be null
     * @return updated invocation parameters containing the security identity
     */
    public static InvocationParameters withIdentity(InvocationParameters existing, SecurityIdentity identity) {
        Objects.requireNonNull(identity, "identity must not be null");
        Map<String, Object> map = new HashMap<>(existing == null ? Map.of() : existing.asMap());
        map.put(KEY_IDENTITY, identity);
        map.put(KEY_TENANT_ID, identity.tenantId());
        map.put(KEY_SUBJECT_ID, identity.subjectId());
        map.put(KEY_ROLES, identity.roles());
        map.put(KEY_CLEARANCE_FLOOR, identity.clearanceFloor());
        if (identity.departmentId() != null && !identity.departmentId().isBlank()) {
            map.put(KEY_DEPARTMENT_ID, identity.departmentId());
        }
        return InvocationParameters.from(map);
    }

    /**
     * Injects a {@link SecurityIdentity} into an existing context map.
     *
     * @param existing the existing context map, may be null
     * @param identity the security identity to inject, must not be null
     * @return updated unmodifiable map containing the security identity
     */
    public static Map<String, Object> withIdentity(Map<String, Object> existing, SecurityIdentity identity) {
        return withIdentity(InvocationParameters.from(existing), identity).asMap();
    }

    /**
     * Extracts a {@link SecurityIdentity} from {@link InvocationParameters}.
     * If the direct identity object is not present, falls back to reconstructing
     * the identity from individual security keys (tenant, subject, roles, clearance).
     *
     * @param parameters the invocation parameters, may be null
     * @return an {@link Optional} containing the extracted identity, or empty if unresolved
     */
    public static Optional<SecurityIdentity> extractIdentity(InvocationParameters parameters) {
        if (parameters == null) {
            return Optional.empty();
        }
        Object directObj = parameters.asMap().get(KEY_IDENTITY);
        if (directObj instanceof SecurityIdentity si) {
            return Optional.of(si);
        }
        return extractFromIndividualKeys(parameters.asMap());
    }

    /**
     * Extracts a {@link SecurityIdentity} from a context map.
     *
     * @param map the context map, may be null
     * @return an {@link Optional} containing the extracted identity, or empty if unresolved
     */
    public static Optional<SecurityIdentity> extractIdentity(Map<String, Object> map) {
        if (map == null) {
            return Optional.empty();
        }
        Object directObj = map.get(KEY_IDENTITY);
        if (directObj instanceof SecurityIdentity si) {
            return Optional.of(si);
        }
        return extractFromIndividualKeys(map);
    }

    /**
     * Extracts a {@link SecurityIdentity} from native LangChain4j {@link dev.langchain4j.invocation.InvocationParameters}.
     *
     * @param parameters native LangChain4j invocation parameters
     * @return an {@link Optional} containing the extracted identity, or empty if unresolved
     */
    public static Optional<SecurityIdentity> extractIdentity(dev.langchain4j.invocation.InvocationParameters parameters) {
        if (parameters == null) {
            return Optional.empty();
        }
        return extractIdentity(parameters.asMap());
    }

    /**
     * Extracts a {@link SecurityIdentity} from a LangChain4j {@link Query}.
     * Inspects query metadata attributes and falls back to ambient {@link SecurityContextHolder}.
     *
     * @param query the query, may be null
     * @return an {@link Optional} containing the extracted identity, or empty if unresolved
     */
    public static Optional<SecurityIdentity> extractIdentity(Query query) {
        if (query == null) {
            return SecurityContextHolder.getIdentity();
        }

        if (query.metadata() != null) {
            dev.langchain4j.invocation.InvocationParameters params = query.metadata().invocationParameters();
            if (params != null) {
                Optional<SecurityIdentity> extracted = extractIdentity(params.asMap());
                if (extracted.isPresent()) {
                    return extracted;
                }
            }

            dev.langchain4j.invocation.InvocationContext context = query.metadata().invocationContext();
            if (context != null && context.invocationParameters() != null) {
                Optional<SecurityIdentity> extracted = extractIdentity(context.invocationParameters().asMap());
                if (extracted.isPresent()) {
                    return extracted;
                }
            }
        }

        return SecurityContextHolder.getIdentity();
    }

    /**
     * Resolves the caller's tenantId from invocation parameters.
     *
     * @param parameters invocation parameters
     * @return Optional tenant ID string
     */
    public static Optional<String> getTenantId(InvocationParameters parameters) {
        if (parameters == null) {
            return Optional.empty();
        }
        return extractIdentity(parameters)
            .map(SecurityIdentity::tenantId)
            .or(() -> parameters.get(KEY_TENANT_ID, String.class));
    }

    /**
     * Resolves the caller's tenantId from a context map.
     *
     * @param map context map
     * @return Optional tenant ID string
     */
    public static Optional<String> getTenantId(Map<String, Object> map) {
        return getTenantId(InvocationParameters.from(map));
    }

    /**
     * Resolves the caller's subjectId from invocation parameters.
     *
     * @param parameters invocation parameters
     * @return Optional subject ID string
     */
    public static Optional<String> getSubjectId(InvocationParameters parameters) {
        if (parameters == null) {
            return Optional.empty();
        }
        return extractIdentity(parameters)
            .map(SecurityIdentity::subjectId)
            .or(() -> parameters.get(KEY_SUBJECT_ID, String.class));
    }

    /**
     * Resolves the caller's subjectId from a context map.
     *
     * @param map context map
     * @return Optional subject ID string
     */
    public static Optional<String> getSubjectId(Map<String, Object> map) {
        return getSubjectId(InvocationParameters.from(map));
    }

    /**
     * Resolves the caller's roles from invocation parameters.
     *
     * @param parameters invocation parameters
     * @return Optional set of role names
     */
    public static Optional<Set<String>> getRoles(InvocationParameters parameters) {
        if (parameters == null) {
            return Optional.empty();
        }
        Optional<Set<String>> fromIdentity = extractIdentity(parameters).map(SecurityIdentity::roles);
        if (fromIdentity.isPresent()) {
            return fromIdentity;
        }
        Object rolesObj = parameters.get(KEY_ROLES).orElse(null);
        if (rolesObj instanceof Collection<?> coll) {
            Set<String> set = new HashSet<>();
            for (Object item : coll) {
                if (item != null) {
                    set.add(item.toString());
                }
            }
            return Optional.of(Set.copyOf(set));
        }
        return Optional.empty();
    }

    /**
     * Resolves the caller's roles from a context map.
     *
     * @param map context map
     * @return Optional set of role names
     */
    public static Optional<Set<String>> getRoles(Map<String, Object> map) {
        return getRoles(InvocationParameters.from(map));
    }

    /**
     * Resolves the caller's clearance floor from invocation parameters.
     *
     * @param parameters invocation parameters
     * @return Optional clearance floor integer
     */
    public static Optional<Integer> getClearanceFloor(InvocationParameters parameters) {
        if (parameters == null) {
            return Optional.empty();
        }
        Optional<Integer> fromIdentity = extractIdentity(parameters).map(SecurityIdentity::clearanceFloor);
        if (fromIdentity.isPresent()) {
            return fromIdentity;
        }
        Object clearanceObj = parameters.get(KEY_CLEARANCE_FLOOR).orElse(null);
        if (clearanceObj instanceof Number num) {
            return Optional.of(num.intValue());
        }
        return Optional.empty();
    }

    /**
     * Resolves the caller's clearance floor from a context map.
     *
     * @param map context map
     * @return Optional clearance floor integer
     */
    public static Optional<Integer> getClearanceFloor(Map<String, Object> map) {
        return getClearanceFloor(InvocationParameters.from(map));
    }

    /**
     * Resolves the caller's departmentId from invocation parameters.
     *
     * @param parameters invocation parameters
     * @return Optional department ID string
     */
    public static Optional<String> getDepartmentId(InvocationParameters parameters) {
        if (parameters == null) {
            return Optional.empty();
        }
        return extractIdentity(parameters)
            .map(SecurityIdentity::departmentId)
            .or(() -> parameters.get(KEY_DEPARTMENT_ID, String.class));
    }

    /**
     * Resolves the caller's departmentId from a context map.
     *
     * @param map context map
     * @return Optional department ID string
     */
    public static Optional<String> getDepartmentId(Map<String, Object> map) {
        return getDepartmentId(InvocationParameters.from(map));
    }

    private static Optional<SecurityIdentity> extractFromIndividualKeys(Map<String, Object> map) {
        Object subjectObj = map.get(KEY_SUBJECT_ID);
        Object tenantObj = map.get(KEY_TENANT_ID);
        if (subjectObj instanceof String sub && tenantObj instanceof String tenant &&
            !sub.isBlank() && !tenant.isBlank()) {
            SecurityIdentity.Builder builder = SecurityIdentity.builder()
                .subjectId(sub)
                .tenantId(tenant);

            Object rolesObj = map.get(KEY_ROLES);
            if (rolesObj instanceof Collection<?> coll) {
                for (Object r : coll) {
                    if (r != null) {
                        builder.addRole(r.toString());
                    }
                }
            }

            Object clearanceObj = map.get(KEY_CLEARANCE_FLOOR);
            if (clearanceObj instanceof Number num) {
                builder.clearanceFloor(num.intValue());
            }

            Object deptObj = map.get(KEY_DEPARTMENT_ID);
            if (deptObj instanceof String dept) {
                builder.departmentId(dept);
            }

            return Optional.of(builder.build());
        }
        return Optional.empty();
    }
}
