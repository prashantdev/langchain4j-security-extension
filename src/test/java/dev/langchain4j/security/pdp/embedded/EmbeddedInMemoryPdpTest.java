package dev.langchain4j.security.pdp.embedded;

import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.PolicyDecision;
import dev.langchain4j.security.pdp.PolicyEvaluationRequest;
import dev.langchain4j.security.pdp.PolicyRule;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class EmbeddedInMemoryPdpTest {

    @Test
    @DisplayName("Should fail-closed on null request or null subject")
    void testFailClosedOnNulls() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();

        assertThat(pdp.evaluate(null)).isEqualTo(PolicyDecision.DENY);

        PolicyEvaluationRequest reqNullSubject = PolicyEvaluationRequest.builder()
            .action("agent:invoke")
            .resource("TestAgent#run")
            .build();
        assertThat(pdp.evaluate(reqNullSubject)).isEqualTo(PolicyDecision.DENY);
    }

    @Test
    @DisplayName("Should evaluate context-supplied constraints from annotations")
    void testContextConstraints() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        pdp.getRoleGraph().addInheritance("SUPER_ADMIN", "ADMIN");

        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user123")
            .tenantId("TENANT_A")
            .roles(Set.of("SUPER_ADMIN"))
            .clearanceFloor(2)
            .build();

        // 1. Role match via transitive expansion -> PERMIT
        PolicyEvaluationRequest reqValid = PolicyEvaluationRequest.builder()
            .subject(identity)
            .action("agent:invoke")
            .resource("TestAgent#run")
            .context(Map.of(
                "requiredRoles", Set.of("ADMIN"),
                "minClearance", 1,
                "requiredTenant", "TENANT_A"
            ))
            .build();
        assertThat(pdp.evaluate(reqValid)).isEqualTo(PolicyDecision.PERMIT);

        // 2. Tenant mismatch -> DENY
        PolicyEvaluationRequest reqTenantMismatch = PolicyEvaluationRequest.builder()
            .subject(identity)
            .action("agent:invoke")
            .resource("TestAgent#run")
            .context(Map.of("requiredTenant", "TENANT_B"))
            .build();
        assertThat(pdp.evaluate(reqTenantMismatch)).isEqualTo(PolicyDecision.DENY);

        // 3. Clearance violation -> DENY
        PolicyEvaluationRequest reqClearanceViolation = PolicyEvaluationRequest.builder()
            .subject(identity)
            .action("agent:invoke")
            .resource("TestAgent#run")
            .context(Map.of("minClearance", 3))
            .build();
        assertThat(pdp.evaluate(reqClearanceViolation)).isEqualTo(PolicyDecision.DENY);

        // 4. Missing required role -> DENY
        PolicyEvaluationRequest reqRoleMissing = PolicyEvaluationRequest.builder()
            .subject(identity)
            .action("agent:invoke")
            .resource("TestAgent#run")
            .context(Map.of("requiredRoles", Set.of("FINANCE_AUDITOR")))
            .build();
        assertThat(pdp.evaluate(reqRoleMissing)).isEqualTo(PolicyDecision.DENY);
    }

    @Test
    @DisplayName("Should enforce strict deny-overrides across registered rules")
    void testStrictDenyOverrides() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();

        SecurityIdentity adminUser = SecurityIdentity.builder()
            .subjectId("admin1")
            .tenantId("TENANT_A")
            .roles(Set.of("ADMIN"))
            .clearanceFloor(3)
            .build();

        // Rule 1: PERMIT rule on tools:* for ADMIN
        pdp.addRule(new PolicyRule(
            "rule-permit-all-tools",
            "tool:execute",
            "tools:*",
            Set.of("ADMIN"),
            1,
            "TENANT_A",
            PolicyDecision.PERMIT
        ));

        // Rule 2: DENY rule on tools:dangerousTool overrides permit
        pdp.addRule(new PolicyRule(
            "rule-deny-dangerous-tool",
            "tool:execute",
            "tools:dangerousTool",
            Set.of(),
            0,
            "",
            PolicyDecision.DENY
        ));

        PolicyEvaluationRequest safeToolReq = PolicyEvaluationRequest.builder()
            .subject(adminUser)
            .action("tool:execute")
            .resource("tools:safeTool")
            .build();
        assertThat(pdp.evaluate(safeToolReq)).isEqualTo(PolicyDecision.PERMIT);

        PolicyEvaluationRequest dangerousToolReq = PolicyEvaluationRequest.builder()
            .subject(adminUser)
            .action("tool:execute")
            .resource("tools:dangerousTool")
            .build();
        assertThat(pdp.evaluate(dangerousToolReq)).isEqualTo(PolicyDecision.DENY);
    }

    @Test
    @DisplayName("Should return NOT_APPLICABLE for unmapped action and resource")
    void testUnmappedRequest() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        pdp.addRule(new PolicyRule(
            "rule-1",
            "agent:invoke",
            "SpecificAgent",
            Set.of(),
            0,
            "",
            PolicyDecision.PERMIT
        ));

        SecurityIdentity user = SecurityIdentity.builder()
            .subjectId("u1")
            .tenantId("t1")
            .build();

        PolicyEvaluationRequest unmappedReq = PolicyEvaluationRequest.builder()
            .subject(user)
            .action("other:action")
            .resource("OtherResource")
            .build();

        assertThat(pdp.evaluate(unmappedReq)).isEqualTo(PolicyDecision.NOT_APPLICABLE);
    }
}
