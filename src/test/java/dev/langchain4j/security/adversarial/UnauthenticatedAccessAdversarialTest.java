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
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.InvocationParameters;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.context.SecurityInvocationParameters;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.retrieval.SecureContentRetriever;
import dev.langchain4j.security.retrieval.SecurityFilterAstBuilder;
import dev.langchain4j.security.retrieval.SecurityMetadataNamespaces;
import dev.langchain4j.security.tool.HardAbortToolExecutionInterceptor;
import dev.langchain4j.security.tool.ToolExecutionDeniedException;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import dev.langchain4j.store.embedding.filter.Filter;
import dev.langchain4j.store.embedding.filter.comparison.IsEqualTo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@DisplayName("Adversarial Test Suite: Unauthenticated Callers Fail-Closed Enforcement")
class UnauthenticatedAccessAdversarialTest {

    @SecuredAgent(requiredRoles = {"OPERATOR"}, minClearance = 1, requiredTenant = "TENANT_ALPHA")
    interface SampleAgentService {
        String process(String request);
        String processWithParams(String request, InvocationParameters params);
    }

    static class SampleAgentServiceImpl implements SampleAgentService {
        @Override
        public String process(String request) {
            return "SUCCESS:" + request;
        }

        @Override
        public String processWithParams(String request, InvocationParameters params) {
            return "SUCCESS_PARAMS:" + request;
        }
    }

    interface SensitiveOperationsTool {
        @SecuredTool(requiredRoles = {"ADMIN"}, minClearance = 2, requiredTenant = "TENANT_ALPHA", isMutative = true)
        void performAction(String payload);
    }

    static class SensitiveOperationsToolImpl implements SensitiveOperationsTool {
        final AtomicBoolean executed = new AtomicBoolean(false);

        @Override
        public void performAction(String payload) {
            executed.set(true);
        }
    }

    @Test
    @DisplayName("Agent Invocation Gate: Fail-closed denial when bound identity and argument identity are both null")
    void testAgentGateRejectsNullCaller() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> audits = new ArrayList<>();
        SecurityAuditPublisher publisher = audits::add;
        SampleAgentService target = new SampleAgentServiceImpl();

        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target,
            SampleAgentService.class,
            pdp,
            publisher,
            null // null bound identity
        );

        SampleAgentService proxy = (SampleAgentService) Proxy.newProxyInstance(
            SampleAgentService.class.getClassLoader(),
            new Class<?>[]{SampleAgentService.class},
            handler
        );

        assertThatThrownBy(() -> proxy.process("malicious-prompt"))
            .isInstanceOf(AgentSecurityException.class)
            .satisfies(ex -> {
                AgentSecurityException ase = (AgentSecurityException) ex;
                assertThat(ase.getReasonCode()).isEqualTo("UNAUTHENTICATED_CALLER");
                assertThat(ase.getIdentity()).isNull();
            });

        assertThat(audits).hasSize(1);
        SecurityAuditEvent event = audits.get(0);
        assertThat(event.decision()).isEqualTo("DENY");
        assertThat(event.enforcementPoint()).isEqualTo("AGENT_GUARD");
        assertThat(event.severity()).isEqualTo("SECURITY_ALERT");
        assertThat(event.reasonCode()).isEqualTo("UNAUTHENTICATED_CALLER");
        assertThat(event.subjectId()).isEqualTo("UNAUTHENTICATED");
    }

    @Test
    @DisplayName("Agent Invocation Gate: Fail-closed denial when InvocationParameters contains empty or non-identity context")
    void testAgentGateRejectsEmptyInvocationParameters() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> audits = new ArrayList<>();
        SecurityAuditPublisher publisher = audits::add;
        SampleAgentService target = new SampleAgentServiceImpl();

        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target,
            SampleAgentService.class,
            pdp,
            publisher,
            null
        );

        SampleAgentService proxy = (SampleAgentService) Proxy.newProxyInstance(
            SampleAgentService.class.getClassLoader(),
            new Class<?>[]{SampleAgentService.class},
            handler
        );

        InvocationParameters emptyParams = InvocationParameters.from(Map.of("custom_key", "custom_val"));

        assertThatThrownBy(() -> proxy.processWithParams("prompt", emptyParams))
            .isInstanceOf(AgentSecurityException.class)
            .satisfies(ex -> {
                AgentSecurityException ase = (AgentSecurityException) ex;
                assertThat(ase.getReasonCode()).isEqualTo("UNAUTHENTICATED_CALLER");
            });
    }

    @Test
    @DisplayName("Tool PEP: Hard abort when identity supplier returns null on secured tool execution")
    void testToolPepHardAbortsUnauthenticatedSupplier() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> audits = new ArrayList<>();
        SecurityAuditPublisher publisher = audits::add;

        SensitiveOperationsToolImpl toolImpl = new SensitiveOperationsToolImpl();
        SensitiveOperationsTool toolProxy = (SensitiveOperationsTool) HardAbortToolExecutionInterceptor.wrap(
            toolImpl,
            pdp,
            publisher,
            () -> null // Supplier provides null identity
        );

        assertThatThrownBy(() -> toolProxy.performAction("inject_code"))
            .isInstanceOf(ToolExecutionDeniedException.class)
            .satisfies(ex -> {
                ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                assertThat(tede.getReasonCode()).isEqualTo("UNAUTHENTICATED_CALLER");
                assertThat(tede.getSubject()).isNull();
                assertThat(tede.getArguments()).containsKey("payload");
                assertThat(tede.getArguments().get("payload")).isEqualTo("inject_code");
            });

        // Ensure target tool was NEVER executed
        assertThat(toolImpl.executed.get()).isFalse();

        assertThat(audits).hasSize(1);
        SecurityAuditEvent event = audits.get(0);
        assertThat(event.decision()).isEqualTo("ABORT");
        assertThat(event.enforcementPoint()).isEqualTo("TOOL_INTERCEPTOR");
        assertThat(event.severity()).isEqualTo("SECURITY_ALERT");
    }

    @Test
    @DisplayName("Retrieval PEP: Unauthenticated query immediately returns empty list without calling underlying ContentRetriever")
    void testRetrievalPepRejectsUnauthenticatedQuery() {
        ContentRetriever mockRetriever = mock(ContentRetriever.class);
        List<SecurityAuditEvent> audits = new ArrayList<>();
        SecurityAuditPublisher publisher = audits::add;

        SecureContentRetriever secureRetriever = SecureContentRetriever.builder()
            .contentRetriever(mockRetriever)
            .securityAuditPublisher(publisher)
            .identitySupplier(() -> null)
            .build();

        Query query = Query.from("Find classified financial report");
        List<Content> results = secureRetriever.retrieve(query);

        assertThat(results).isNotNull().isEmpty();
        verify(mockRetriever, never()).retrieve(any(Query.class));

        assertThat(audits).hasSize(1);
        SecurityAuditEvent event = audits.get(0);
        assertThat(event.decision()).isEqualTo("DENY");
        assertThat(event.enforcementPoint()).isEqualTo("RAG_FILTER");
        assertThat(event.reasonCode()).isEqualTo("UNAUTHENTICATED_RETRIEVAL_DENIED");
    }

    @Test
    @DisplayName("Retrieval Filter AST: Null or anonymous identity compiles to sentinel deny-all filter")
    void testFilterAstBuilderSentinelOnAnonymousAndNull() {
        Filter nullFilter = SecurityFilterAstBuilder.buildFilter(null);
        assertThat(nullFilter).isInstanceOf(IsEqualTo.class);
        IsEqualTo eqNull = (IsEqualTo) nullFilter;
        assertThat(eqNull.key()).isEqualTo(SecurityMetadataNamespaces.TENANT_ID);
        assertThat(eqNull.comparisonValue()).isEqualTo(SecurityMetadataNamespaces.DENY_ALL_SENTINEL);

        SecurityIdentity anon = SecurityIdentity.anonymous("TENANT_X");
        Filter anonFilter = SecurityFilterAstBuilder.buildFilter(anon);
        assertThat(anonFilter).isInstanceOf(IsEqualTo.class);
        IsEqualTo eqAnon = (IsEqualTo) anonFilter;
        assertThat(eqAnon.key()).isEqualTo(SecurityMetadataNamespaces.TENANT_ID);
        assertThat(eqAnon.comparisonValue()).isEqualTo(SecurityMetadataNamespaces.DENY_ALL_SENTINEL);
    }
}
