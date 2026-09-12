package dev.langchain4j.security.retrieval;

import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.SecurityIdentity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static dev.langchain4j.security.retrieval.SecurityMetadataNamespaces.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class SecureContentRetrieverTest {

    @Test
    @DisplayName("Should immediately return empty list and fail-closed when caller is unauthenticated")
    void testUnauthenticatedRetrieval() {
        ContentRetriever mockDelegate = Mockito.mock(ContentRetriever.class);
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SecureContentRetriever retriever = SecureContentRetriever.builder()
            .contentRetriever(mockDelegate)
            .securityAuditPublisher(publisher)
            .identitySupplier(() -> null) // unauthenticated
            .build();

        Query query = Query.from("financial projections");
        List<Content> results = retriever.retrieve(query);

        assertThat(results).isEmpty();
        verify(mockDelegate, never()).retrieve(Mockito.any());

        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo("DENY");
        assertThat(auditLogs.get(0).reasonCode()).isEqualTo("UNAUTHENTICATED_RETRIEVAL_DENIED");
    }

    @Test
    @DisplayName("Should prune cross-tenant chunks, unlabelled chunks, and higher clearance chunks in memory")
    void testPostRetrievalPruning() {
        ContentRetriever mockDelegate = Mockito.mock(ContentRetriever.class);
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SecurityIdentity user = SecurityIdentity.builder()
            .subjectId("alice")
            .tenantId("TENANT_CORP")
            .roles(Set.of("EMPLOYEE"))
            .clearanceFloor(1)
            .departmentId("ENGINEERING")
            .build();

        // 1. Authorized chunk (matches tenant, clearance <= 1, role EMPLOYEE, dept ENGINEERING)
        Metadata meta1 = Metadata.from(Map.of(
            TENANT_ID, "TENANT_CORP",
            CLEARANCE_FLOOR, 1,
            ALLOWED_ROLES, "[EMPLOYEE]",
            DEPARTMENT_ID, "ENGINEERING"
        ));
        Content validContent = Content.from(TextSegment.from("Valid chunk", meta1));

        // 2. Cross-tenant chunk (TENANT_OTHER)
        Metadata meta2 = Metadata.from(Map.of(
            TENANT_ID, "TENANT_OTHER",
            CLEARANCE_FLOOR, 1,
            ALLOWED_ROLES, "[EMPLOYEE]"
        ));
        Content crossTenantContent = Content.from(TextSegment.from("Cross tenant chunk", meta2));

        // 3. Higher clearance chunk (clearance 2 > caller 1)
        Metadata meta3 = Metadata.from(Map.of(
            TENANT_ID, "TENANT_CORP",
            CLEARANCE_FLOOR, 2,
            ALLOWED_ROLES, "[EMPLOYEE]"
        ));
        Content highClearanceContent = Content.from(TextSegment.from("Secret chunk", meta3));

        // 4. Role mismatch chunk
        Metadata meta4 = Metadata.from(Map.of(
            TENANT_ID, "TENANT_CORP",
            CLEARANCE_FLOOR, 1,
            ALLOWED_ROLES, "[EXECUTIVE]"
        ));
        Content roleMismatchContent = Content.from(TextSegment.from("Executive only chunk", meta4));

        // 5. Unlabelled chunk (missing metadata)
        Content unlabelledContent = Content.from(TextSegment.from("Unlabelled chunk"));

        Query query = Query.from("System documentation");
        Mockito.when(mockDelegate.retrieve(query)).thenReturn(List.of(
            validContent, crossTenantContent, highClearanceContent, roleMismatchContent, unlabelledContent
        ));

        SecureContentRetriever retriever = SecureContentRetriever.builder()
            .contentRetriever(mockDelegate)
            .securityAuditPublisher(publisher)
            .identitySupplier(() -> user)
            .build();

        List<Content> result = retriever.retrieve(query);

        // Only chunk 1 should survive pruning
        assertThat(result).hasSize(1);
        assertThat(result.get(0).textSegment().text()).isEqualTo("Valid chunk");

        // 4 chunks pruned -> audit record emitted
        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).reasonCode()).isEqualTo("RAG_UNAUTHORIZED_PRUNING");
        assertThat(auditLogs.get(0).payloadSnapshot().get("prunedCount")).isEqualTo(4);
    }
}
