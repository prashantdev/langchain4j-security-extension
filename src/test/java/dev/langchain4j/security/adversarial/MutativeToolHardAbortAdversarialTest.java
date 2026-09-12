package dev.langchain4j.security.adversarial;

import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.tool.HardAbortToolExecutionInterceptor;
import dev.langchain4j.security.tool.ToolExecutionDeniedException;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Adversarial Test Suite: Mutative Tool Hard Abort & Side-Effect Prevention")
class MutativeToolHardAbortAdversarialTest {

    interface CriticalInfrastructureTool {
        @SecuredTool(requiredRoles = {"INFRA_ADMIN"}, minClearance = 3, requiredTenant = "CORP_INFRA", isMutative = true)
        void purgeAllUserData(String realm);

        @SecuredTool(requiredRoles = {"FINANCE_SUPERVISOR"}, minClearance = 2, requiredTenant = "CORP_INFRA", isMutative = true)
        double transferFunds(String sourceAccount, String destinationAccount, double amount);

        @SecuredTool(requiredRoles = {"AUDITOR"}, minClearance = 1, requiredTenant = "CORP_INFRA", isMutative = false)
        String readAuditLog(String logId);
    }

    static class CriticalInfrastructureToolImpl implements CriticalInfrastructureTool {
        final List<String> purgedRealms = new ArrayList<>();
        final Map<String, Double> balances = new HashMap<>();
        final AtomicInteger executionCount = new AtomicInteger(0);

        CriticalInfrastructureToolImpl() {
            balances.put("ACC_SOURCE", 1_000_000.0);
            balances.put("ACC_DEST", 0.0);
        }

        @Override
        public void purgeAllUserData(String realm) {
            executionCount.incrementAndGet();
            purgedRealms.add(realm);
        }

        @Override
        public double transferFunds(String sourceAccount, String destinationAccount, double amount) {
            executionCount.incrementAndGet();
            double src = balances.getOrDefault(sourceAccount, 0.0);
            balances.put(sourceAccount, src - amount);
            double dst = balances.getOrDefault(destinationAccount, 0.0);
            balances.put(destinationAccount, dst + amount);
            return amount;
        }

        @Override
        public String readAuditLog(String logId) {
            executionCount.incrementAndGet();
            return "LOG_RECORD_" + logId;
        }
    }

    @Test
    @DisplayName("Mutative Tool Hard Abort: Unauthorized purgeAllUserData causes ZERO side effects and captures arguments")
    void testMutativePurgeSideEffectsStrictlyPrevented() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> audits = new ArrayList<>();
        SecurityAuditPublisher publisher = audits::add;

        CriticalInfrastructureToolImpl statefulTool = new CriticalInfrastructureToolImpl();

        // Caller has role OPERATOR and clearance 1 (insufficient for INFRA_ADMIN and clearance 3)
        SecurityIdentity attacker = SecurityIdentity.builder()
            .subjectId("rogue_operator")
            .tenantId("CORP_INFRA")
            .roles(Set.of("OPERATOR"))
            .clearanceFloor(1)
            .build();

        CriticalInfrastructureTool proxy = (CriticalInfrastructureTool) HardAbortToolExecutionInterceptor.wrap(
            statefulTool, pdp, publisher, () -> attacker
        );

        assertThatThrownBy(() -> proxy.purgeAllUserData("PRODUCTION_CUSTOMER_DATA"))
            .isInstanceOf(ToolExecutionDeniedException.class)
            .satisfies(ex -> {
                ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                assertThat(tede.getReasonCode()).isEqualTo("TOOL_EXECUTION_DENIED");
                assertThat(tede.getSubject().subjectId()).isEqualTo("rogue_operator");
                assertThat(tede.getToolName()).contains("CriticalInfrastructureToolImpl#purgeAllUserData");

                // Argument verification
                assertThat(tede.getArguments()).containsKey("realm");
                assertThat(tede.getArguments().get("realm")).isEqualTo("PRODUCTION_CUSTOMER_DATA");
            });

        // Verify strict side-effect prevention: tool was NEVER invoked, state remains clean
        assertThat(statefulTool.executionCount.get()).isZero();
        assertThat(statefulTool.purgedRealms).isEmpty();

        // Verify audit trail
        assertThat(audits).hasSize(1);
        SecurityAuditEvent event = audits.get(0);
        assertThat(event.decision()).isEqualTo("ABORT");
        assertThat(event.severity()).isEqualTo("SECURITY_ALERT");
        assertThat(event.action()).isEqualTo("tool:execute");
        assertThat(event.payloadSnapshot()).containsKey("realm");
    }

    @Test
    @DisplayName("Mutative Tool Hard Abort: Unauthorized funds transfer leaves balances untouched")
    void testMutativeFundsTransferBalancesUnchanged() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        CriticalInfrastructureToolImpl statefulTool = new CriticalInfrastructureToolImpl();

        // Attacker lacks FINANCE_SUPERVISOR
        SecurityIdentity attacker = SecurityIdentity.builder()
            .subjectId("unauthorized_teller")
            .tenantId("CORP_INFRA")
            .roles(Set.of("TELLER"))
            .clearanceFloor(2)
            .build();

        CriticalInfrastructureTool proxy = (CriticalInfrastructureTool) HardAbortToolExecutionInterceptor.wrap(
            statefulTool, pdp, null, () -> attacker
        );

        assertThatThrownBy(() -> proxy.transferFunds("ACC_SOURCE", "ACC_DEST", 500_000.0))
            .isInstanceOf(ToolExecutionDeniedException.class)
            .satisfies(ex -> {
                ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                assertThat(tede.getArguments()).containsEntry("sourceAccount", "ACC_SOURCE");
                assertThat(tede.getArguments()).containsEntry("destinationAccount", "ACC_DEST");
                assertThat(tede.getArguments()).containsEntry("amount", 500_000.0);
            });

        // Balances must remain exactly at initial values
        assertThat(statefulTool.balances.get("ACC_SOURCE")).isEqualTo(1_000_000.0);
        assertThat(statefulTool.balances.get("ACC_DEST")).isEqualTo(0.0);
        assertThat(statefulTool.executionCount.get()).isZero();
    }

    @Test
    @DisplayName("Authorized Call: Mutative operation completes and updates state when authorized")
    void testAuthorizedMutativeToolSucceeds() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        CriticalInfrastructureToolImpl statefulTool = new CriticalInfrastructureToolImpl();

        SecurityIdentity supervisor = SecurityIdentity.builder()
            .subjectId("alice_supervisor")
            .tenantId("CORP_INFRA")
            .roles(Set.of("FINANCE_SUPERVISOR"))
            .clearanceFloor(2)
            .build();

        CriticalInfrastructureTool proxy = (CriticalInfrastructureTool) HardAbortToolExecutionInterceptor.wrap(
            statefulTool, pdp, null, () -> supervisor
        );

        double transferred = proxy.transferFunds("ACC_SOURCE", "ACC_DEST", 250_000.0);
        assertThat(transferred).isEqualTo(250_000.0);

        assertThat(statefulTool.balances.get("ACC_SOURCE")).isEqualTo(750_000.0);
        assertThat(statefulTool.balances.get("ACC_DEST")).isEqualTo(250_000.0);
        assertThat(statefulTool.executionCount.get()).isEqualTo(1);
    }
}
