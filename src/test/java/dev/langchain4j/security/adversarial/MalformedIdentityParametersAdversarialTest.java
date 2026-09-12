package dev.langchain4j.security.adversarial;

import dev.langchain4j.security.context.InvocationParameters;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.context.SecurityInvocationParameters;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Adversarial Test Suite: Missing Context & Malformed Identity Parameters")
class MalformedIdentityParametersAdversarialTest {

    @Test
    @DisplayName("SecurityIdentity: Rejects null or blank subjectId and tenantId with IllegalArgumentException")
    void testSubjectAndTenantValidation() {
        assertThatThrownBy(() -> new SecurityIdentity(null, "tenant1", Set.of(), 0, null, Map.of()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("subjectId");

        assertThatThrownBy(() -> new SecurityIdentity("   ", "tenant1", Set.of(), 0, null, Map.of()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("subjectId");

        assertThatThrownBy(() -> new SecurityIdentity("sub1", null, Set.of(), 0, null, Map.of()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("tenantId");

        assertThatThrownBy(() -> new SecurityIdentity("sub1", "\t\n ", Set.of(), 0, null, Map.of()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("tenantId");
    }

    @Test
    @DisplayName("Immutability & Defensive Copying: Identity roles and attributes cannot be mutated externally")
    void testDefensiveCopyingAndImmutability() {
        Set<String> mutableRoles = new HashSet<>(Arrays.asList("ROLE_A", "ROLE_B"));
        Map<String, Object> mutableAttrs = new HashMap<>();
        mutableAttrs.put("tier", "gold");

        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user1")
            .tenantId("tenant1")
            .roles(mutableRoles)
            .attributes(mutableAttrs)
            .build();

        // Mutate original sets
        mutableRoles.add("ROLE_MUTATED");
        mutableAttrs.put("tier", "platinum");

        // Identity must remain unaffected
        assertThat(identity.roles()).doesNotContain("ROLE_MUTATED");
        assertThat(identity.getAttribute("tier")).contains("gold");

        // Mutating returned view must throw UnsupportedOperationException
        assertThatThrownBy(() -> identity.roles().add("NEW_ROLE"))
            .isInstanceOf(UnsupportedOperationException.class);

        assertThatThrownBy(() -> identity.attributes().put("hacked", "value"))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Malformed Roles & Attributes: Null or empty elements are filtered without throwing NPE")
    void testMalformedCollectionsFiltering() {
        Set<String> malformedRoles = new HashSet<>();
        malformedRoles.add("VALID_ROLE");
        malformedRoles.add(null);
        malformedRoles.add("  ");

        Map<String, Object> malformedAttrs = new HashMap<>();
        malformedAttrs.put("valid_key", "valid_val");
        malformedAttrs.put(null, "null_key");
        malformedAttrs.put("null_val", null);

        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user_malformed")
            .tenantId("tenant_malformed")
            .roles(malformedRoles)
            .attributes(malformedAttrs)
            .build();

        assertThat(identity.roles()).containsExactly("VALID_ROLE");
        assertThat(identity.attributes()).containsOnlyKeys("valid_key");
    }

    @Test
    @DisplayName("SecurityInvocationParameters: Malformed map extraction resilience")
    void testMalformedMapExtractionResilience() {
        // Missing subject or tenant
        Map<String, Object> missingSubject = Map.of(SecurityInvocationParameters.KEY_TENANT_ID, "tenant1");
        assertThat(SecurityInvocationParameters.extractIdentity(missingSubject)).isEmpty();

        Map<String, Object> missingTenant = Map.of(SecurityInvocationParameters.KEY_SUBJECT_ID, "user1");
        assertThat(SecurityInvocationParameters.extractIdentity(missingTenant)).isEmpty();

        // Malformed clearance floor (e.g. non-number string or invalid object)
        Map<String, Object> invalidClearanceMap = Map.of(
            SecurityInvocationParameters.KEY_SUBJECT_ID, "user1",
            SecurityInvocationParameters.KEY_TENANT_ID, "tenant1",
            SecurityInvocationParameters.KEY_CLEARANCE_FLOOR, "NOT_A_NUMBER"
        );
        Optional<SecurityIdentity> extracted = SecurityInvocationParameters.extractIdentity(invalidClearanceMap);
        assertThat(extracted).isPresent();
        // Defaults to 0 when clearance floor key is not a Number
        assertThat(extracted.get().clearanceFloor()).isZero();

        // Null map input returns empty
        assertThat(SecurityInvocationParameters.extractIdentity((Map<String, Object>) null)).isEmpty();
        assertThat(SecurityInvocationParameters.extractIdentity((InvocationParameters) null)).isEmpty();
    }

    @Test
    @DisplayName("Round-trip Context Serialization: withIdentity -> extractIdentity recreates identical identity")
    void testRoundTripSerialization() {
        SecurityIdentity original = SecurityIdentity.builder()
            .subjectId("alice")
            .tenantId("FINANCE_CORP")
            .addRole("ANALYST")
            .addRole("AUDITOR")
            .clearanceFloor(2)
            .departmentId("RISK_MGMT")
            .addAttribute("region", "US-EAST")
            .build();

        InvocationParameters packed = SecurityInvocationParameters.withIdentity(InvocationParameters.empty(), original);
        Optional<SecurityIdentity> roundTripped = SecurityInvocationParameters.extractIdentity(packed);

        assertThat(roundTripped).isPresent();
        SecurityIdentity extracted = roundTripped.get();
        assertThat(extracted.subjectId()).isEqualTo(original.subjectId());
        assertThat(extracted.tenantId()).isEqualTo(original.tenantId());
        assertThat(extracted.roles()).isEqualTo(original.roles());
        assertThat(extracted.clearanceFloor()).isEqualTo(original.clearanceFloor());
        assertThat(extracted.departmentId()).isEqualTo(original.departmentId());
    }
}
