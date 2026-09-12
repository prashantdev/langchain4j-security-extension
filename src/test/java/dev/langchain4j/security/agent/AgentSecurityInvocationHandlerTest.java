package dev.langchain4j.security.agent;

import dev.langchain4j.security.agent.annotation.SecuredAgent;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AgentSecurityInvocationHandlerTest {

    @SecuredAgent(requiredRoles = {"AGENT_USER"}, minClearance = 1, requiredTenant = "CORP_TENANT")
    interface SampleAgent {
        String answer(String question);

        @SecuredAgent(requiredRoles = {"AGENT_ADMIN"}, minClearance = 2, requiredTenant = "CORP_TENANT")
        String adminTask(String task);

        String answerWithIdentity(String question, SecurityIdentity identity);
    }

    static class SampleAgentImpl implements SampleAgent {
        @Override
        public String answer(String question) {
            return "Answer: " + question;
        }

        @Override
        public String adminTask(String task) {
            return "Done: " + task;
        }

        @Override
        public String answerWithIdentity(String question, SecurityIdentity identity) {
            return "Response to " + identity.subjectId();
        }
    }

    @Test
    @DisplayName("Should allow authorized caller to invoke secured agent")
    void testAuthorizedInvocation() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SecurityIdentity user = SecurityIdentity.builder()
            .subjectId("alice")
            .tenantId("CORP_TENANT")
            .roles(Set.of("AGENT_USER"))
            .clearanceFloor(1)
            .build();

        SampleAgent target = new SampleAgentImpl();
        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target, SampleAgent.class, pdp, publisher, user
        );

        SampleAgent proxy = (SampleAgent) Proxy.newProxyInstance(
            SampleAgent.class.getClassLoader(),
            new Class<?>[]{SampleAgent.class},
            handler
        );

        String result = proxy.answer("What is the weather?");
        assertThat(result).isEqualTo("Answer: What is the weather?");

        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo("ALLOW");
        assertThat(auditLogs.get(0).severity()).isEqualTo("INFORMATIONAL");
        assertThat(auditLogs.get(0).reasonCode()).isEqualTo("AGENT_ACCESS_PERMITTED");
    }

    @Test
    @DisplayName("Should throw AgentSecurityException when unauthenticated caller invokes secured agent")
    void testUnauthenticatedInvocation() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SampleAgent target = new SampleAgentImpl();
        // boundIdentity is null
        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target, SampleAgent.class, pdp, publisher, null
        );

        SampleAgent proxy = (SampleAgent) Proxy.newProxyInstance(
            SampleAgent.class.getClassLoader(),
            new Class<?>[]{SampleAgent.class},
            handler
        );

        assertThatThrownBy(() -> proxy.answer("Hello?"))
            .isInstanceOf(AgentSecurityException.class)
            .satisfies(ex -> {
                AgentSecurityException ase = (AgentSecurityException) ex;
                assertThat(ase.getReasonCode()).isEqualTo("UNAUTHENTICATED_CALLER");
            });

        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo("DENY");
        assertThat(auditLogs.get(0).severity()).isEqualTo("SECURITY_ALERT");
    }

    @Test
    @DisplayName("Should throw AgentSecurityException when caller role is unauthorized")
    void testUnauthorizedRoleInvocation() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SecurityIdentity standardUser = SecurityIdentity.builder()
            .subjectId("bob")
            .tenantId("CORP_TENANT")
            .roles(Set.of("AGENT_USER"))
            .clearanceFloor(1)
            .build();

        SampleAgent target = new SampleAgentImpl();
        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target, SampleAgent.class, pdp, publisher, standardUser
        );

        SampleAgent proxy = (SampleAgent) Proxy.newProxyInstance(
            SampleAgent.class.getClassLoader(),
            new Class<?>[]{SampleAgent.class},
            handler
        );

        // adminTask requires AGENT_ADMIN role
        assertThatThrownBy(() -> proxy.adminTask("restart cluster"))
            .isInstanceOf(AgentSecurityException.class)
            .satisfies(ex -> {
                AgentSecurityException ase = (AgentSecurityException) ex;
                assertThat(ase.getReasonCode()).isEqualTo("AGENT_AUTHORIZATION_FAILED");
                assertThat(ase.getIdentity().subjectId()).isEqualTo("bob");
            });

        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo("DENY");
        assertThat(auditLogs.get(0).severity()).isEqualTo("SECURITY_ALERT");
    }

    @Test
    @DisplayName("Should extract caller identity passed in method arguments")
    void testInBandArgumentIdentityExtraction() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        // Handler has null boundIdentity, but identity is passed in args
        SampleAgent target = new SampleAgentImpl();
        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target, SampleAgent.class, pdp, publisher, null
        );

        SampleAgent proxy = (SampleAgent) Proxy.newProxyInstance(
            SampleAgent.class.getClassLoader(),
            new Class<?>[]{SampleAgent.class},
            handler
        );

        SecurityIdentity user = SecurityIdentity.builder()
            .subjectId("charlie")
            .tenantId("CORP_TENANT")
            .roles(Set.of("AGENT_USER"))
            .clearanceFloor(1)
            .build();

        String res = proxy.answerWithIdentity("Ping", user);
        assertThat(res).isEqualTo("Response to charlie");
        assertThat(auditLogs.get(0).decision()).isEqualTo("ALLOW");
    }
}
