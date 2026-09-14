package dev.langchain4j.security.e2e;

import dev.langchain4j.agent.tool.Tool;
import dev.langchain4j.agent.tool.ToolExecutionRequest;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.chat.request.ChatRequest;
import dev.langchain4j.model.chat.response.ChatResponse;
import dev.langchain4j.security.agent.AgentSecurityException;
import dev.langchain4j.security.agent.SecureAiServices;
import dev.langchain4j.security.agent.annotation.SecuredAgent;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.tool.HardAbortToolExecutionInterceptor;
import dev.langchain4j.security.tool.ToolExecutionDeniedException;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class SecureAiServicesE2ETest {

    private static final String ROLE_SUPPORT_TIER_1 = "SUPPORT_TIER_1";
    private static final String ROLE_FINANCE_ADMIN = "FINANCE_ADMIN";
    private static final String TENANT_CORP_FINANCE = "CORP_FINANCE";
    private static final String SUBJECT_ALICE = "alice";
    private static final String SUBJECT_TIER1_AGENT = "tier1_agent";
    private static final String REASON_UNAUTHENTICATED_CALLER = "UNAUTHENTICATED_CALLER";
    private static final String REASON_TOOL_EXECUTION_DENIED = "TOOL_EXECUTION_DENIED";
    private static final String DECISION_ALLOW = "ALLOW";
    private static final String DECISION_DENY = "DENY";

    @SecuredAgent(requiredRoles = {ROLE_SUPPORT_TIER_1}, minClearance = 1, requiredTenant = TENANT_CORP_FINANCE)
    public interface FinancialSupportAgent {
        String chat(String message);
    }

    public interface BankingOperations {
        @Tool("Executes a wire transfer")
        @SecuredTool(requiredRoles = {ROLE_FINANCE_ADMIN}, minClearance = 3, requiredTenant = TENANT_CORP_FINANCE, isMutative = true)
        String executeWireTransfer(String recipient, double amount);
    }

    public static class BankingOperationsImpl implements BankingOperations {
        @Override
        public String executeWireTransfer(String recipient, double amount) {
            return "Transferred $" + amount + " to " + recipient;
        }
    }

    private ChatModel createMockChatModel(String replyText) {
        return Mockito.mock(ChatModel.class, invocation -> {
            if ("chat".equals(invocation.getMethod().getName())) {
                Class<?> returnType = invocation.getMethod().getReturnType();
                if (returnType == String.class) {
                    return replyText;
                }
                if (returnType == ChatResponse.class) {
                    return ChatResponse.builder()
                        .aiMessage(AiMessage.from(replyText))
                        .build();
                }
            }
            return Mockito.RETURNS_DEFAULTS.answer(invocation);
        });
    }

    @Test
    @DisplayName("E2E: Unauthenticated caller cannot invoke secured agent interface")
    void testUnauthenticatedInvocationBlocked() {
        ChatModel mockModel = createMockChatModel("Hello! How can I help you?");
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        FinancialSupportAgent agent = SecureAiServices.builder(FinancialSupportAgent.class)
            .chatModel(mockModel)
            .policyDecisionEngine(pdp)
            .securityAuditPublisher(publisher)
            // identity is not set (unauthenticated)
            .build();

        assertThatThrownBy(() -> agent.chat("Check my balance"))
            .isInstanceOf(AgentSecurityException.class)
            .satisfies(ex -> {
                AgentSecurityException ase = (AgentSecurityException) ex;
                assertThat(ase.getReasonCode()).isEqualTo(REASON_UNAUTHENTICATED_CALLER);
            });

        // Model should never be invoked
        verify(mockModel, never()).chat(Mockito.any(ChatRequest.class));
        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo(DECISION_DENY);
    }

    @Test
    @DisplayName("E2E: Authorized user invokes agent successfully")
    void testAuthorizedAgentInvocation() {
        ChatModel mockModel = createMockChatModel("Welcome to Support!");

        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SecurityIdentity authorizedUser = SecurityIdentity.builder()
            .subjectId(SUBJECT_ALICE)
            .tenantId(TENANT_CORP_FINANCE)
            .roles(Set.of(ROLE_SUPPORT_TIER_1))
            .clearanceFloor(1)
            .build();

        FinancialSupportAgent agent = SecureAiServices.builder(FinancialSupportAgent.class)
            .chatModel(mockModel)
            .policyDecisionEngine(pdp)
            .securityAuditPublisher(publisher)
            .securityIdentity(authorizedUser)
            .build();

        String reply = agent.chat("Hello");
        assertThat(reply).isEqualTo("Welcome to Support!");

        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo(DECISION_ALLOW);
    }

    @Test
    @DisplayName("E2E: Interceptor hard-aborts mutative tool when agent caller lacks required role")
    void testMutativeToolExecutionHardAborted() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        // Caller has SUPPORT_TIER_1 (clearance 1), but executeWireTransfer requires FINANCE_ADMIN (clearance 3)
        SecurityIdentity supportCaller = SecurityIdentity.builder()
            .subjectId(SUBJECT_TIER1_AGENT)
            .tenantId(TENANT_CORP_FINANCE)
            .roles(Set.of(ROLE_SUPPORT_TIER_1))
            .clearanceFloor(1)
            .build();

        BankingOperations rawTool = Mockito.spy(new BankingOperationsImpl());
        BankingOperations wrappedTool = (BankingOperations) HardAbortToolExecutionInterceptor.wrap(
            rawTool, pdp, publisher, () -> supportCaller
        );

        assertThatThrownBy(() -> wrappedTool.executeWireTransfer("adversary-acct", 500000.0))
            .isInstanceOf(ToolExecutionDeniedException.class)
            .satisfies(ex -> {
                ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                assertThat(tede.getReasonCode()).isEqualTo(REASON_TOOL_EXECUTION_DENIED);
                assertThat(tede.getSubject().subjectId()).isEqualTo(SUBJECT_TIER1_AGENT);
            });

        // The actual mutative business operation was never executed
        verify(rawTool, never()).executeWireTransfer("adversary-acct", 500000.0);
    }

    @Test
    @DisplayName("E2E: Full AiServices pipeline hard-aborts mutative tool execution requested by mocked LLM")
    void testE2EMutativeToolExecutionHardAbortedViaAiServices() {
        ToolExecutionRequest toolExecutionRequest = ToolExecutionRequest.builder()
            .id("tool-call-1")
            .name("executeWireTransfer")
            .arguments("{\"recipient\": \"adversary-acct\", \"amount\": 500000.0}")
            .build();

        java.util.concurrent.atomic.AtomicInteger callCount = new java.util.concurrent.atomic.AtomicInteger(0);

        ChatModel mockModel = Mockito.mock(ChatModel.class, invocation -> {
            if ("chat".equals(invocation.getMethod().getName())) {
                Class<?> returnType = invocation.getMethod().getReturnType();
                if (returnType == ChatResponse.class) {
                    if (callCount.getAndIncrement() == 0) {
                        return ChatResponse.builder()
                            .aiMessage(AiMessage.from(toolExecutionRequest))
                            .build();
                    } else {
                        return ChatResponse.builder()
                            .aiMessage(AiMessage.from("Operation failed due to security deny."))
                            .build();
                    }
                }
            }
            return Mockito.RETURNS_DEFAULTS.answer(invocation);
        });

        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SecurityIdentity supportUser = SecurityIdentity.builder()
            .subjectId(SUBJECT_TIER1_AGENT)
            .tenantId(TENANT_CORP_FINANCE)
            .roles(Set.of(ROLE_SUPPORT_TIER_1))
            .clearanceFloor(1)
            .build();

        BankingOperations rawTool = Mockito.spy(new BankingOperationsImpl());

        FinancialSupportAgent agent = SecureAiServices.builder(FinancialSupportAgent.class)
            .chatModel(mockModel)
            .tools(rawTool)
            .policyDecisionEngine(pdp)
            .securityAuditPublisher(publisher)
            .securityIdentity(supportUser)
            .build();

        try {
            agent.chat("Transfer money to adversary-acct");
        } catch (Exception ignored) {
        }

        // Verify the mutative tool method was intercepted and never invoked
        verify(rawTool, never()).executeWireTransfer("adversary-acct", 500000.0);

        // Verify audit log captured the tool execution denial
        assertThat(auditLogs).anySatisfy(log -> {
            assertThat(log.enforcementPoint()).isEqualTo("TOOL_INTERCEPTOR");
            assertThat(log.decision()).isEqualTo("ABORT");
            assertThat(log.reasonCode()).isEqualTo("TOOL_POLICY_VIOLATION");
        });
    }
}

