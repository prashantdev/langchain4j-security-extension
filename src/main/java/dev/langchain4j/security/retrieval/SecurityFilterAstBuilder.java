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

    /**
     * Translates caller SecurityIdentity into a native LangChain4j Filter AST tree.
     *
     * @param identity caller SecurityIdentity
     * @return constructed security Filter
     */
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

    /**
     * Combines an existing user filter with a security filter via a logical AND operation.
     *
     * @param existingFilter user-supplied Filter, or null
     * @param securityFilter security Filter, or null
     * @return combined Filter AST
     */
    public static Filter combineWithExisting(Filter existingFilter, Filter securityFilter) {
        if (existingFilter == null) {
            return securityFilter;
        }
        if (securityFilter == null) {
            return existingFilter;
        }
        return and(existingFilter, securityFilter);
    }

    /**
     * Constructs an {@link IsEqualTo} filter for the specified metadata key and value.
     *
     * @param key metadata field name
     * @param value comparison target value
     * @return IsEqualTo filter
     */
    public static Filter isEqualTo(String key, Object value) {
        return new IsEqualTo(key, value);
    }

    /**
     * Constructs an {@link IsLessThanOrEqualTo} filter for the specified metadata key and maximum value threshold.
     *
     * @param key metadata field name
     * @param value maximum comparison value
     * @return IsLessThanOrEqualTo filter
     */
    @SuppressWarnings("unchecked")
    public static Filter isLessThanOrEqualTo(String key, Comparable<?> value) {
        return new IsLessThanOrEqualTo(key, (Comparable) value);
    }

    /**
     * Constructs an {@link IsIn} filter for the specified metadata key and target collection of permitted values.
     *
     * @param key metadata field name
     * @param values collection of permitted values
     * @return IsIn filter
     */
    public static Filter isIn(String key, Collection<?> values) {
        return new IsIn(key, values);
    }

    /**
     * Combines two {@link Filter} instances into a logical {@link And} predicate AST.
     *
     * @param left left operand filter
     * @param right right operand filter
     * @return And logical filter
     */
    public static Filter and(Filter left, Filter right) {
        return new And(left, right);
    }
}
