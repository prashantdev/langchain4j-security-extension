package dev.langchain4j.security.tool;

import dev.langchain4j.security.context.SecurityContextHolder;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.PolicyDecisionEngine;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConcreteToolClassInterceptionTest {

    private PolicyDecisionEngine pdp;

    // Concrete POJO class without Java interfaces
    public static class ConcreteSystemTool {

        @SecuredTool(
            action = "tool:execute",
            requiredRoles = {"ADMIN"},
            minClearance = 2,
            requiredTenant = "tenant-alpha",
            isMutative = true
        )
        public String rebootServer(String serverId) {
            return "Rebooted " + serverId;
        }

        public String pingServer(String serverId) {
            return "Pong " + serverId;
        }
    }

    @BeforeEach
    void setUp() {
        pdp = new EmbeddedInMemoryPdp();
        SecurityContextHolder.clear();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clear();
    }

    @Test
    @DisplayName("Concrete POJO tool class without interfaces is proxied via ByteBuddy and enforces @SecuredTool")
    void testConcreteToolClassInterception_DenyUnauthenticated() throws Exception {
        ConcreteSystemTool rawTool = new ConcreteSystemTool();
        Object wrappedObj = HardAbortToolExecutionInterceptor.wrap(rawTool, pdp, null, () -> SecurityContextHolder.getIdentity().orElse(null));

        assertThat(wrappedObj).isNotNull();
        assertThat(wrappedObj.getClass()).isNotEqualTo(ConcreteSystemTool.class); // ByteBuddy subclass proxy

        Method rebootMethod = ConcreteSystemTool.class.getMethod("rebootServer", String.class);

        // Expect Hard Abort exception when caller is unauthenticated
        assertThatThrownBy(() -> {
            HardAbortToolExecutionInterceptor interceptor = new HardAbortToolExecutionInterceptor(rawTool, pdp, null, null);
            interceptor.beforeToolExecution(rebootMethod, new Object[]{"server-01"}, null);
        }).isInstanceOf(ToolExecutionDeniedException.class)
          .hasMessageContaining("Unauthenticated caller");
    }

    @Test
    @DisplayName("Concrete POJO tool allows execution when caller satisfies security requirements")
    void testConcreteToolClassInterception_PermitAuthorized() throws Exception {
        ConcreteSystemTool rawTool = new ConcreteSystemTool();

        SecurityIdentity adminIdentity = SecurityIdentity.builder()
            .subjectId("admin-user")
            .tenantId("tenant-alpha")
            .addRole("ADMIN")
            .clearanceFloor(3)
            .build();

        SecurityContextHolder.setIdentity(adminIdentity);

        Method rebootMethod = ConcreteSystemTool.class.getMethod("rebootServer", String.class);
        HardAbortToolExecutionInterceptor interceptor = new HardAbortToolExecutionInterceptor(rawTool, pdp, null, null);

        // Should execute cleanly without exception
        interceptor.beforeToolExecution(rebootMethod, new Object[]{"server-01"}, adminIdentity);
    }
}
