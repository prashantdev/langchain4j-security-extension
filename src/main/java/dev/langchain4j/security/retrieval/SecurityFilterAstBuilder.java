package dev.langchain4j.security.retrieval;

import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.store.embedding.filter.Filter;
import dev.langchain4j.store.embedding.filter.comparison.IsEqualTo;
import dev.langchain4j.store.embedding.filter.comparison.IsIn;
import dev.langchain4j.store.embedding.filter.comparison.IsLessThanOrEqualTo;
import dev.langchain4j.store.embedding.filter.logical.And;

import java.util.Collection;

import static dev.langchain4j.security.retrieval.SecurityMetadataNamespaces.*;

/**
 * Translates caller {@link SecurityIdentity} into native LangChain4j  {@link Filter} AST trees.
 */
public final class SecurityFilterAstBuilder {

    private SecurityFilterAstBuilder() {}

    public static Filter buildFilter(SecurityIdentity identity) {
        // Fail-closed default for unauthenticated/anonymous caller: Sentinel Deny-All Filter
        if (identity == null || identity.subjectId().equalsIgnoreCase(SecurityIdentity.ANONYMOUS_SUBJECT)) {
            return isEqualTo(TENANT_ID, DENY_ALL_SENTINEL);
        }

        // 1. Strict Tenant isolation predicate
        Filter tenantFilter = isEqualTo(TENANT_ID, identity.tenantId());

        // 2. Clearance floor rank predicate
        Filter clearanceFilter = isLessThanOrEqualTo(CLEARANCE_FLOOR, identity.clearanceFloor());

        Filter composite = and(tenantFilter, clearanceFilter);

        // 3. Allowed roles predicate (if roles present)
        if (!identity.roles().isEmpty()) {
            Filter rolesFilter = isIn(ALLOWED_ROLES, identity.roles());
            composite = and(composite, rolesFilter);
        }

        // 4. Department ID predicate (optional if present)
        if (identity.departmentId() != null && !identity.departmentId().isBlank()) {
            Filter deptFilter = isEqualTo(DEPARTMENT_ID, identity.departmentId());
            composite = and(composite, deptFilter);
        }

        return composite;
    }

    public static Filter combineWithExisting(Filter existingFilter, Filter securityFilter) {
        if (existingFilter == null) {
            return securityFilter;
        }
        if (securityFilter == null) {
            return existingFilter;
        }
        return and(existingFilter, securityFilter);
    }

    public static Filter isEqualTo(String key, Object value) {
        return new IsEqualTo(key, value);
    }

    @SuppressWarnings("unchecked")
    public static Filter isLessThanOrEqualTo(String key, Comparable<?> value) {
        return new IsLessThanOrEqualTo(key, (Comparable) value);
    }

    public static Filter isIn(String key, Collection<?> values) {
        return new IsIn(key, values);
    }

    public static Filter and(Filter left, Filter right) {
        return new And(left, right);
    }
}
