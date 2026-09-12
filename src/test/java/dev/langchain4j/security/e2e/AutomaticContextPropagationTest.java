package dev.langchain4j.security.e2e;

import dev.langchain4j.security.agent.AgentSecurityInvocationHandler;
import dev.langchain4j.security.agent.annotation.SecuredAgent;
import dev.langchain4j.security.context.SecurityContextHolder;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.PolicyDecisionEngine;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;

import static org.assertj.core.api.Assertions.assertThat;

class AutomaticContextPropagationTest {

    @SecuredAgent(
        requiredRoles = {"OPERATOR"},
        minClearance = 1,
        requiredTenant = "tenant-ops"
    )
    public interface OpsAgentService {
        String executeTask(String taskName);
    }

    public static class OpsAgentServiceImpl implements OpsAgentService {
        @Override
        public String executeTask(String taskName) {
            // Verify that SecurityContextHolder automatically captured the caller identity
            SecurityIdentity currentIdentity = SecurityContextHolder.getIdentity().orElse(null);
            if (currentIdentity != null) {
                return "Executed " + taskName + " by " + currentIdentity.subjectId();
            }
            return "Executed " + taskName + " anonymously";
        }
    }

    private PolicyDecisionEngine pdp;

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
    @DisplayName("AgentSecurityInvocationHandler automatically propagates SecurityIdentity to SecurityContextHolder during turn")
    void testAutomaticContextPropagation() {
        OpsAgentService rawImpl = new OpsAgentServiceImpl();

        SecurityIdentity callerIdentity = SecurityIdentity.builder()
            .subjectId("operator-user")
            .tenantId("tenant-ops")
            .addRole("OPERATOR")
            .clearanceFloor(2)
            .build();

        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            rawImpl,
            OpsAgentService.class,
            pdp,
            null,
            callerIdentity
        );

        OpsAgentService proxy = (OpsAgentService) Proxy.newProxyInstance(
            OpsAgentService.class.getClassLoader(),
            new Class<?>[]{OpsAgentService.class},
            handler
        );

        String result = proxy.executeTask("system-diagnostic");

        assertThat(result).isEqualTo("Executed system-diagnostic by operator-user");

        // Verify context is cleanly removed after turn execution completes
        assertThat(SecurityContextHolder.getIdentity()).isEmpty();
    }
}
