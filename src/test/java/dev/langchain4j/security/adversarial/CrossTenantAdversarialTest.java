package dev.langchain4j.security.adversarial;

import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import dev.langchain4j.security.agent.AgentSecurityException;
import dev.langchain4j.security.agent.AgentSecurityInvocationHandler;
import dev.langchain4j.security.agent.annotation.SecuredAgent;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.retrieval.SecureContentRetriever;
import dev.langchain4j.security.retrieval.SecurityFilterAstBuilder;
import dev.langchain4j.security.retrieval.SecurityMetadataNamespaces;
import dev.langchain4j.security.tool.HardAbortToolExecutionInterceptor;
import dev.langchain4j.security.tool.ToolExecutionDeniedException;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import dev.langchain4j.store.embedding.filter.Filter;
import dev.langchain4j.store.embedding.filter.comparison.IsEqualTo;
import dev.langchain4j.store.embedding.filter.logical.And;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("Adversarial Test Suite: Cross-Tenant Data Isolation & Parameter Forgery")
class CrossTenantAdversarialTest {

    @SecuredAgent(requiredTenant = "TENANT_LEGAL")
    interface LegalAdvisorAgent {
        String reviewContract(String contractId);
    }

    static class LegalAdvisorAgentImpl implements LegalAdvisorAgent {
        @Override
        public String reviewContract(String contractId) {
            return "REVIEWED:" + contractId;
        }
    }

    interface CrossTenantAccountTool {
        @SecuredTool(requiredTenant = "TENANT_ENTERPRISE", isMutative = true)
        String transferAccount(String targetTenant, String accountId);
    }

    static class CrossTenantAccountToolImpl implements CrossTenantAccountTool {
        @Override
        public String transferAccount(String targetTenant, String accountId) {
            return "TRANSFERRED:" + accountId + " to " + targetTenant;
        }
    }

    @Test
    @DisplayName("Cross-Tenant Retrieval Pruning: Purges foreign tenant, empty tenant, and missing metadata chunks")
    void testPostRetrievalPrunesCrossTenantChunks() {
        ContentRetriever mockRetriever = mock(ContentRetriever.class);
        List<SecurityAuditEvent> audits = new ArrayList<>();

        SecurityIdentity tenantAIdentity = SecurityIdentity.builder()
            .subjectId("user_tenant_a")
            .tenantId("TENANT_A")
            .clearanceFloor(3)
            .build();

        // Simulate a vector store that returned mixed chunks (e.g., due to index leakage or malicious embedding)
        Content c1 = Content.from(TextSegment.from("Valid Tenant A chunk",
            Metadata.from(Map.of(SecurityMetadataNamespaces.TENANT_ID, "TENANT_A"))));

        Content c2 = Content.from(TextSegment.from("Foreign Tenant B chunk",
            Metadata.from(Map.of(SecurityMetadataNamespaces.TENANT_ID, "TENANT_B"))));

        Content c3 = Content.from(TextSegment.from("Foreign Tenant C chunk",
            Metadata.from(Map.of(SecurityMetadataNamespaces.TENANT_ID, "TENANT_C"))));

        Content c4 = Content.from(TextSegment.from("Missing sec:tenant_id chunk",
            Metadata.from(Map.of("author", "john"))));

        Content c5 = Content.from(TextSegment.from("Blank tenant chunk",
            Metadata.from(Map.of(SecurityMetadataNamespaces.TENANT_ID, ""))));

        Content c6 = Content.from(TextSegment.from("Empty metadata chunk", Metadata.from(Map.of())));

        when(mockRetriever.retrieve(any(Query.class))).thenReturn(List.of(c1, c2, c3, c4, c5, c6));

        SecureContentRetriever secureRetriever = SecureContentRetriever.builder()
            .contentRetriever(mockRetriever)
            .securityAuditPublisher(audits::add)
            .identitySupplier(() -> tenantAIdentity)
            .build();

        List<Content> filtered = secureRetriever.retrieve(Query.from("fetch data"));

        // Only c1 should survive
        assertThat(filtered).hasSize(1);
        assertThat(filtered.get(0).textSegment().text()).isEqualTo("Valid Tenant A chunk");

        // Audit check: 5 chunks pruned
        assertThat(audits).hasSize(1);
        SecurityAuditEvent event = audits.get(0);
        assertThat(event.reasonCode()).isEqualTo("RAG_UNAUTHORIZED_PRUNING");
        assertThat(event.payloadSnapshot()).containsEntry("totalFetched", 6);
        assertThat(event.payloadSnapshot()).containsEntry("prunedCount", 5);
        assertThat(event.tenantId()).isEqualTo("TENANT_A");
    }

    @Test
    @DisplayName("Retrieval AST Filter: Generates strict tenant predicate and combines cleanly with user filter")
    void testAstFilterEnforcesTenant() {
        SecurityIdentity id = SecurityIdentity.builder()
            .subjectId("user1")
            .tenantId("FINANCE_CORP")
            .clearanceFloor(1)
            .build();

        Filter filter = SecurityFilterAstBuilder.buildFilter(id);
        assertThat(filter).isInstanceOf(And.class);

        // Verify combineWithExisting preserves security filter
        Filter userFilter = SecurityFilterAstBuilder.isEqualTo("category", "reports");
        Filter combined = SecurityFilterAstBuilder.combineWithExisting(userFilter, filter);
        assertThat(combined).isInstanceOf(And.class);
    }

    @Test
    @DisplayName("Tool Parameter Forgery: Caller from TENANT_RETAIL attempting to invoke tool for TENANT_ENTERPRISE is denied")
    void testCrossTenantToolParameterForgeryDenied() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> audits = new ArrayList<>();

        // Caller belongs to TENANT_RETAIL
        SecurityIdentity retailUser = SecurityIdentity.builder()
            .subjectId("retail_user_1")
            .tenantId("TENANT_RETAIL")
            .build();

        CrossTenantAccountTool rawTool = new CrossTenantAccountToolImpl();
        CrossTenantAccountTool proxy = (CrossTenantAccountTool) HardAbortToolExecutionInterceptor.wrap(
            rawTool, pdp, audits::add, () -> retailUser
        );

        // Caller attempts to execute transfer claiming targetTenant is TENANT_ENTERPRISE
        assertThatThrownBy(() -> proxy.transferAccount("TENANT_ENTERPRISE", "acc-456"))
            .isInstanceOf(ToolExecutionDeniedException.class)
            .satisfies(ex -> {
                ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                assertThat(tede.getReasonCode()).isEqualTo("TOOL_EXECUTION_DENIED");
                assertThat(tede.getSubject().tenantId()).isEqualTo("TENANT_RETAIL");
                assertThat(tede.getArguments()).containsKey("targetTenant");
            });

        assertThat(audits).hasSize(1);
        assertThat(audits.get(0).decision()).isEqualTo("ABORT");
    }

    @Test
    @DisplayName("Agent Tenant Guard: Cross-tenant invocation is blocked before entering agent method")
    void testCrossTenantAgentInvocationBlocked() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> audits = new ArrayList<>();

        SecurityIdentity medicalUser = SecurityIdentity.builder()
            .subjectId("dr_house")
            .tenantId("TENANT_MEDICAL")
            .build();

        LegalAdvisorAgent target = new LegalAdvisorAgentImpl();
        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target, LegalAdvisorAgent.class, pdp, audits::add, medicalUser
        );

        LegalAdvisorAgent proxy = (LegalAdvisorAgent) Proxy.newProxyInstance(
            LegalAdvisorAgent.class.getClassLoader(), new Class<?>[]{LegalAdvisorAgent.class}, handler
        );

        assertThatThrownBy(() -> proxy.reviewContract("contract-007"))
            .isInstanceOf(AgentSecurityException.class)
            .satisfies(ex -> {
                AgentSecurityException ase = (AgentSecurityException) ex;
                assertThat(ase.getReasonCode()).isEqualTo("AGENT_AUTHORIZATION_FAILED");
                assertThat(ase.getIdentity().tenantId()).isEqualTo("TENANT_MEDICAL");
            });

        assertThat(audits).hasSize(1);
        assertThat(audits.get(0).decision()).isEqualTo("DENY");
    }

    @Test
    @DisplayName("Missing Tenant Parameter: Rejection on creation of SecurityIdentity")
    void testBlankOrNullTenantIdRejected() {
        assertThatThrownBy(() -> SecurityIdentity.builder().subjectId("user").tenantId(null).build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("tenantId");

        assertThatThrownBy(() -> SecurityIdentity.builder().subjectId("user").tenantId("   ").build())
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("tenantId");
    }
}
