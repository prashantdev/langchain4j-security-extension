package dev.langchain4j.security.retrieval;

import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import dev.langchain4j.security.context.SecurityContextHolder;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.store.embedding.filter.Filter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Collections;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;

class SecureContentRetrieverAstPreFilterTest {

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clear();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clear();
    }

    @Test
    @DisplayName("SecureContentRetriever.dynamicFilterProvider creates valid Filter AST for authenticated caller")
    void testDynamicFilterProvider_Authenticated() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("auditor-01")
            .tenantId("tenant-corp")
            .addRole("AUDITOR")
            .clearanceFloor(2)
            .departmentId("SECURITY")
            .build();

        SecurityContextHolder.setIdentity(identity);

        Function<Query, Filter> filterProvider = SecureContentRetriever.dynamicFilterProvider();
        Query query = Query.from("Security policy document");

        Filter ast = filterProvider.apply(query);

        assertThat(ast).isNotNull();
        assertThat(ast.toString()).contains("sec:tenant_id");
        assertThat(ast.toString()).contains("tenant-corp");
        assertThat(ast.toString()).contains("sec:clearance_floor");
    }

    @Test
    @DisplayName("SecureContentRetriever.dynamicFilterProvider returns sentinel deny-all filter for unauthenticated caller")
    void testDynamicFilterProvider_Unauthenticated() {
        Function<Query, Filter> filterProvider = SecureContentRetriever.dynamicFilterProvider();
        Query query = Query.from("Confidential financial report");

        Filter ast = filterProvider.apply(query);

        assertThat(ast).isNotNull();
        assertThat(ast.toString()).contains(SecurityMetadataNamespaces.DENY_ALL_SENTINEL);
    }

    @Test
    @DisplayName("SecureContentRetriever.buildAstFilter builds AST filter and handles unauthenticated queries fail-closed")
    void testSecureContentRetriever_UnauthenticatedFailClosed() {
        ContentRetriever mockDelegate = Mockito.mock(ContentRetriever.class);
        SecureContentRetriever retriever = SecureContentRetriever.builder()
            .contentRetriever(mockDelegate)
            .build();

        Query query = Query.from("Anonymous search query");

        var results = retriever.retrieve(query);

        assertThat(results).isEmpty();
        Mockito.verifyNoInteractions(mockDelegate);
    }
}
