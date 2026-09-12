package dev.langchain4j.security.tool;

import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class HardAbortToolExecutionInterceptorTest {

    interface OperationsTool {
        @SecuredTool(requiredRoles = {"OPERATOR"}, minClearance = 1, requiredTenant = "CORP_A", isMutative = false)
        String getStatus(String serviceId);

        @SecuredTool(requiredRoles = {"DEVOPS_ADMIN"}, minClearance = 3, requiredTenant = "CORP_A", isMutative = true)
        void deleteDatabase(String dbName, boolean confirm);
    }

    @Test
    @DisplayName("Should permit authorized caller to execute tool")
    void testAuthorizedToolExecution() {
        OperationsTool mockTool = Mockito.mock(OperationsTool.class);
        Mockito.when(mockTool.getStatus("srv-1")).thenReturn("HEALTHY");

        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        SecurityIdentity operator = SecurityIdentity.builder()
            .subjectId("op1")
            .tenantId("CORP_A")
            .roles(Set.of("OPERATOR"))
            .clearanceFloor(1)
            .build();

        OperationsTool proxy = (OperationsTool) HardAbortToolExecutionInterceptor.wrap(
            mockTool, pdp, publisher, () -> operator
        );

        String status = proxy.getStatus("srv-1");
        assertThat(status).isEqualTo("HEALTHY");
        verify(mockTool).getStatus("srv-1");

        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo("ALLOW");
        assertThat(auditLogs.get(0).reasonCode()).isEqualTo("TOOL_EXECUTE_PERMITTED");
    }

    @Test
    @DisplayName("Should hard-abort mutative tool and ensure target method is NEVER invoked when unauthorized")
    void testMutativeToolHardAbort() {
        OperationsTool mockTool = Mockito.mock(OperationsTool.class);

        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        List<SecurityAuditEvent> auditLogs = new ArrayList<>();
        SecurityAuditPublisher publisher = auditLogs::add;

        // Operator has clearance 1 and role OPERATOR, but deleteDatabase requires DEVOPS_ADMIN and clearance 3
        SecurityIdentity operator = SecurityIdentity.builder()
            .subjectId("op1")
            .tenantId("CORP_A")
            .roles(Set.of("OPERATOR"))
            .clearanceFloor(1)
            .build();

        OperationsTool proxy = (OperationsTool) HardAbortToolExecutionInterceptor.wrap(
            mockTool, pdp, publisher, () -> operator
        );

        assertThatThrownBy(() -> proxy.deleteDatabase("prod-db", true))
            .isInstanceOf(ToolExecutionDeniedException.class)
            .satisfies(ex -> {
                ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                assertThat(tede.getReasonCode()).isEqualTo("TOOL_EXECUTION_DENIED");
                assertThat(tede.getSubject().subjectId()).isEqualTo("op1");
                assertThat(tede.getArguments()).containsKey("dbName");
                assertThat(tede.getArguments().get("dbName")).isEqualTo("prod-db");
            });

        // Verify zero invocations of deleteDatabase
        verify(mockTool, never()).deleteDatabase(Mockito.anyString(), Mockito.anyBoolean());

        assertThat(auditLogs).hasSize(1);
        assertThat(auditLogs.get(0).decision()).isEqualTo("ABORT");
        assertThat(auditLogs.get(0).severity()).isEqualTo("SECURITY_ALERT");
    }

    @Test
    @DisplayName("Should throw ToolExecutionDeniedException on tenant mismatch")
    void testTenantMismatchAbort() {
        OperationsTool mockTool = Mockito.mock(OperationsTool.class);
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();

        // Caller belongs to CORP_B, but tool requires CORP_A
        SecurityIdentity foreignUser = SecurityIdentity.builder()
            .subjectId("attacker")
            .tenantId("CORP_B")
            .roles(Set.of("OPERATOR"))
            .clearanceFloor(1)
            .build();

        OperationsTool proxy = (OperationsTool) HardAbortToolExecutionInterceptor.wrap(
            mockTool, pdp, null, () -> foreignUser
        );

        assertThatThrownBy(() -> proxy.getStatus("srv-1"))
            .isInstanceOf(ToolExecutionDeniedException.class);
        verify(mockTool, never()).getStatus(Mockito.anyString());
    }

    @Test
    @DisplayName("Should throw ToolExecutionDeniedException on unauthenticated tool execution")
    void testUnauthenticatedToolExecution() {
        OperationsTool mockTool = Mockito.mock(OperationsTool.class);
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();

        AtomicReference<SecurityIdentity> idRef = new AtomicReference<>(null);
        OperationsTool proxy = (OperationsTool) HardAbortToolExecutionInterceptor.wrap(
            mockTool, pdp, null, idRef::get
        );

        assertThatThrownBy(() -> proxy.getStatus("srv-1"))
            .isInstanceOf(ToolExecutionDeniedException.class)
            .satisfies(ex -> {
                ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                assertThat(tede.getReasonCode()).isEqualTo("UNAUTHENTICATED_CALLER");
            });
        verify(mockTool, never()).getStatus(Mockito.anyString());
    }
}
