package dev.langchain4j.security.adversarial;

import dev.langchain4j.security.agent.AgentSecurityException;
import dev.langchain4j.security.agent.AgentSecurityInvocationHandler;
import dev.langchain4j.security.agent.annotation.SecuredAgent;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.PolicyDecision;
import dev.langchain4j.security.pdp.PolicyEvaluationRequest;
import dev.langchain4j.security.pdp.PolicyRule;
import dev.langchain4j.security.pdp.embedded.ClearanceLattice;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.pdp.embedded.RoleGraph;
import dev.langchain4j.security.tool.HardAbortToolExecutionInterceptor;
import dev.langchain4j.security.tool.ToolExecutionDeniedException;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Adversarial Test Suite: Unauthorized Role Escalation & Cycle Attacks")
class RoleEscalationAdversarialTest {

    @SecuredAgent(requiredRoles = {"SYSTEM_ADMIN"}, minClearance = 2, requiredTenant = "CORP_HQ")
    interface AdminAgent {
        String executeAdminCommand(String cmd);
    }

    static class AdminAgentImpl implements AdminAgent {
        @Override
        public String executeAdminCommand(String cmd) {
            return "EXECUTED:" + cmd;
        }
    }

    interface SecurityAdministrationTool {
        @SecuredTool(requiredRoles = {"SECOPS_LEAD"}, minClearance = 3, requiredTenant = "CORP_HQ", isMutative = true)
        String revokeCertificate(String certId);
    }

    static class SecurityAdministrationToolImpl implements SecurityAdministrationTool {
        @Override
        public String revokeCertificate(String certId) {
            return "REVOKED:" + certId;
        }
    }

    @Test
    @DisplayName("Direct Role Escalation: Unprivileged user cannot invoke agent requiring SYSTEM_ADMIN")
    void testDirectRoleEscalationDenied() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> audits = new ArrayList<>();

        SecurityIdentity standardUser = SecurityIdentity.builder()
            .subjectId("attacker_bob")
            .tenantId("CORP_HQ")
            .roles(Set.of("STANDARD_USER", "GUEST"))
            .clearanceFloor(2)
            .build();

        AdminAgent target = new AdminAgentImpl();
        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            target, AdminAgent.class, pdp, audits::add, standardUser
        );

        AdminAgent proxy = (AdminAgent) Proxy.newProxyInstance(
            AdminAgent.class.getClassLoader(), new Class<?>[]{AdminAgent.class}, handler
        );

        assertThatThrownBy(() -> proxy.executeAdminCommand("shutdown"))
            .isInstanceOf(AgentSecurityException.class)
            .satisfies(ex -> {
                AgentSecurityException ase = (AgentSecurityException) ex;
                assertThat(ase.getReasonCode()).isEqualTo("AGENT_AUTHORIZATION_FAILED");
            });

        assertThat(audits).hasSize(1);
        assertThat(audits.get(0).decision()).isEqualTo("DENY");
    }

    @Test
    @DisplayName("Reverse Role DAG Attack: Child role cannot assume Parent role privileges")
    void testReverseRoleInheritanceDenied() {
        RoleGraph roleGraph = new RoleGraph();
        // C-LEVEL inherits VP_ENGINEERING, which inherits TECH_LEAD, which inherits DEVELOPER
        roleGraph.addInheritance("C_LEVEL", "VP_ENGINEERING");
        roleGraph.addInheritance("VP_ENGINEERING", "TECH_LEAD");
        roleGraph.addInheritance("TECH_LEAD", "DEVELOPER");

        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp(roleGraph, new ClearanceLattice());

        // Attacker is assigned DEVELOPER (leaf child role)
        SecurityIdentity devUser = SecurityIdentity.builder()
            .subjectId("dev_charlie")
            .tenantId("CORP_HQ")
            .roles(Set.of("DEVELOPER"))
            .clearanceFloor(3)
            .build();

        SecurityAdministrationTool target = new SecurityAdministrationToolImpl();
        SecurityAdministrationTool proxy = (SecurityAdministrationTool) HardAbortToolExecutionInterceptor.wrap(
            target, pdp, null, () -> devUser
        );

        // SecurityAdministrationTool requires SECOPS_LEAD or let's test against TECH_LEAD tool
        assertThat(roleGraph.hasRole(devUser.roles(), "TECH_LEAD")).isFalse();
        assertThat(roleGraph.hasRole(devUser.roles(), "VP_ENGINEERING")).isFalse();
        assertThat(roleGraph.hasRole(devUser.roles(), "C_LEVEL")).isFalse();

        // Attacker with DEVELOPER attempting tool requiring SECOPS_LEAD is blocked
        assertThatThrownBy(() -> proxy.revokeCertificate("cert-999"))
            .isInstanceOf(ToolExecutionDeniedException.class);
    }

    @Test
    @DisplayName("Sibling Role Isolation: Sibling branches in Role DAG cannot assume each other's roles")
    void testSiblingRoleIsolation() {
        RoleGraph roleGraph = new RoleGraph();
        roleGraph.addInheritance("ROOT_ADMIN", "FINANCE_DEPT");
        roleGraph.addInheritance("ROOT_ADMIN", "ENGINEERING_DEPT");

        // FINANCE_DEPT does NOT inherit ENGINEERING_DEPT
        Set<String> financeRoles = roleGraph.expandRoles(Set.of("FINANCE_DEPT"));
        assertThat(financeRoles).contains("FINANCE_DEPT");
        assertThat(financeRoles).doesNotContain("ENGINEERING_DEPT");
        assertThat(financeRoles).doesNotContain("ROOT_ADMIN");

        assertThat(roleGraph.hasRole(Set.of("FINANCE_DEPT"), "ENGINEERING_DEPT")).isFalse();
        assertThat(roleGraph.hasRole(Set.of("ENGINEERING_DEPT"), "FINANCE_DEPT")).isFalse();
    }

    @Test
    @DisplayName("Cycle Detection Attack: Multi-node cyclic role inheritance is detected and blocked")
    void testMultiNodeCycleDetection() {
        RoleGraph roleGraph = new RoleGraph();
        roleGraph.addInheritance("ROLE_A", "ROLE_B");
        roleGraph.addInheritance("ROLE_B", "ROLE_C");
        roleGraph.addInheritance("ROLE_C", "ROLE_D");
        roleGraph.addInheritance("ROLE_D", "ROLE_E");

        // Attempting to close the loop: ROLE_E -> ROLE_A
        assertThatThrownBy(() -> roleGraph.addInheritance("ROLE_E", "ROLE_A"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Cyclic role inheritance detected");

        // Attempting intermediate loop: ROLE_D -> ROLE_B
        assertThatThrownBy(() -> roleGraph.addInheritance("ROLE_D", "ROLE_B"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Cyclic role inheritance detected");

        // Verify graph remains functional after failed cycle injection
        Set<String> expanded = roleGraph.expandRoles(Set.of("ROLE_A"));
        assertThat(expanded).containsExactlyInAnyOrder("ROLE_A", "ROLE_B", "ROLE_C", "ROLE_D", "ROLE_E");
    }

    @Test
    @DisplayName("Case Manipulation & Whitespace: Role matching normalizes case and whitespace across DAG")
    void testCaseAndWhitespaceNormalization() {
        RoleGraph roleGraph = new RoleGraph();
        roleGraph.addInheritance("  Global_Admin  ", "  secops_specialist  ");
        Set<String> expanded = roleGraph.expandRoles(Set.of("global_admin"));
        assertThat(expanded.contains("SECOPS_SPECIALIST")).isTrue();
        assertThat(expanded.contains("secops_specialist")).isTrue();
        assertThat(roleGraph.hasRole(Set.of("GLOBAL_ADMIN"), "SECOPS_SPECIALIST")).isTrue();
        assertThat(roleGraph.hasRole(Set.of("global_admin"), "secops_specialist")).isTrue();
        assertThat(roleGraph.hasRole(Set.of("  GLOBAL_ADMIN  "), "  secops_specialist  ")).isTrue();
    }

    @Test
    @DisplayName("Strict Deny-Overrides: PDP DENY rule overrides matching PERMIT rule")
    void testStrictDenyOverrides() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();

        // Add broad permit rule
        pdp.addRule(new PolicyRule(
            "rule-permit-all",
            "tool:*",
            "OperationsTool#*",
            Set.of(),
            0,
            "TENANT_1",
            PolicyDecision.PERMIT
        ));

        // Add specific deny rule for adversary subject
        pdp.addRule(new PolicyRule(
            "rule-deny-restricted",
            "tool:execute",
            "OperationsTool#restrictedOperation",
            Set.of(),
            0,
            "TENANT_1",
            PolicyDecision.DENY
        ));

        SecurityIdentity user = SecurityIdentity.builder()
            .subjectId("user1")
            .tenantId("TENANT_1")
            .build();

        PolicyEvaluationRequest req = PolicyEvaluationRequest.builder()
            .subject(user)
            .action("tool:execute")
            .resource("OperationsTool#restrictedOperation")
            .build();

        PolicyDecision decision = pdp.evaluate(req);
        assertThat(decision).isEqualTo(PolicyDecision.DENY);
    }
}
