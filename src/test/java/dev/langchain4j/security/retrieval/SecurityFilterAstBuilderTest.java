package dev.langchain4j.security.retrieval;

import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.store.embedding.filter.Filter;
import dev.langchain4j.store.embedding.filter.comparison.IsEqualTo;
import dev.langchain4j.store.embedding.filter.logical.And;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static dev.langchain4j.security.retrieval.SecurityMetadataNamespaces.*;
import static org.assertj.core.api.Assertions.assertThat;

class SecurityFilterAstBuilderTest {

    @Test
    @DisplayName("Should generate Deny-All Sentinel Filter when caller is null or anonymous")
    void testDenyAllSentinelOnAnonymousOrNull() {
        Filter filterNull = SecurityFilterAstBuilder.buildFilter(null);
        assertThat(filterNull).isInstanceOf(IsEqualTo.class);
        IsEqualTo eqNull = (IsEqualTo) filterNull;
        assertThat(eqNull.key()).isEqualTo(TENANT_ID);
        assertThat(eqNull.comparisonValue()).isEqualTo(DENY_ALL_SENTINEL);

        SecurityIdentity anon = SecurityIdentity.anonymous("CORP_1");
        Filter filterAnon = SecurityFilterAstBuilder.buildFilter(anon);
        assertThat(filterAnon).isInstanceOf(IsEqualTo.class);
        IsEqualTo eqAnon = (IsEqualTo) filterAnon;
        assertThat(eqAnon.key()).isEqualTo(TENANT_ID);
        assertThat(eqAnon.comparisonValue()).isEqualTo(DENY_ALL_SENTINEL);
    }

    @Test
    @DisplayName("Should generate composite Filter AST for authenticated caller with tenant and clearance")
    void testAuthenticatedCallerFilter() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("alice")
            .tenantId("TENANT_A")
            .clearanceFloor(2)
            .build();

        Filter filter = SecurityFilterAstBuilder.buildFilter(identity);
        assertThat(filter).isInstanceOf(And.class);
    }

    @Test
    @DisplayName("Should include roles and department when present on caller identity")
    void testRolesAndDepartmentFilter() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("bob")
            .tenantId("TENANT_B")
            .roles(Set.of("ROLE_FINANCE", "ROLE_LEGAL"))
            .clearanceFloor(3)
            .departmentId("DEPT_LEGAL")
            .build();

        Filter filter = SecurityFilterAstBuilder.buildFilter(identity);
        assertThat(filter).isInstanceOf(And.class);
    }

    @Test
    @DisplayName("Should cleanly combine existing query filter with security filter")
    void testCombineWithExisting() {
        Filter existing = SecurityFilterAstBuilder.isEqualTo("doc_type", "pdf");
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("charlie")
            .tenantId("TENANT_C")
            .clearanceFloor(1)
            .build();

        Filter securityFilter = SecurityFilterAstBuilder.buildFilter(identity);
        Filter combined = SecurityFilterAstBuilder.combineWithExisting(existing, securityFilter);

        assertThat(combined).isInstanceOf(And.class);
        And andFilter = (And) combined;
        assertThat(andFilter.left()).isEqualTo(existing);
        assertThat(andFilter.right()).isEqualTo(securityFilter);

        // Null checks
        assertThat(SecurityFilterAstBuilder.combineWithExisting(null, securityFilter)).isEqualTo(securityFilter);
        assertThat(SecurityFilterAstBuilder.combineWithExisting(existing, null)).isEqualTo(existing);
        assertThat(SecurityFilterAstBuilder.combineWithExisting(null, null)).isNull();
    }
}
