package dev.langchain4j.security.context;

import dev.langchain4j.rag.query.Query;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityInvocationParametersTest {

    @Test
    @DisplayName("AC 1.3: Packing SecurityIdentity via withIdentity and extracting yields identical object")
    void testPackingAndRoundTripExtraction() {
        SecurityIdentity original = SecurityIdentity.builder()
            .subjectId("subject-99")
            .tenantId("tenant-corp")
            .addRole("ROLE_AUDITOR")
            .addRole("ROLE_USER")
            .clearanceFloor(2)
            .departmentId("compliance")
            .addAttribute("region", "EMEA")
            .build();

        InvocationParameters baseParams = InvocationParameters.from(Map.of("customAppKey", "customAppVal"));
        InvocationParameters packedParams = SecurityInvocationParameters.withIdentity(baseParams, original);

        // Verify custom parameters are preserved
        assertThat(packedParams.get("customAppKey", String.class)).contains("customAppVal");

        // Verify round-trip extraction
        Optional<SecurityIdentity> extracted = SecurityInvocationParameters.extractIdentity(packedParams);
        assertThat(extracted).isPresent().contains(original);
        assertThat(extracted.get().roles()).containsExactlyInAnyOrder("ROLE_AUDITOR", "ROLE_USER");
        assertThat(extracted.get().clearanceFloor()).isEqualTo(2);
        assertThat(extracted.get().departmentId()).isEqualTo("compliance");

        // Verify individual getters
        assertThat(SecurityInvocationParameters.getTenantId(packedParams)).contains("tenant-corp");
        assertThat(SecurityInvocationParameters.getSubjectId(packedParams)).contains("subject-99");
        assertThat(SecurityInvocationParameters.getRoles(packedParams)).contains(Set.of("ROLE_AUDITOR", "ROLE_USER"));
        assertThat(SecurityInvocationParameters.getClearanceFloor(packedParams)).contains(2);
        assertThat(SecurityInvocationParameters.getDepartmentId(packedParams)).contains("compliance");
    }

    @Test
    @DisplayName("Map-based withIdentity and extractIdentity work identically to InvocationParameters")
    void testMapBasedWithIdentityAndExtract() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("sub-map")
            .tenantId("tenant-map")
            .addRole("ROLE_ENGINEER")
            .clearanceFloor(1)
            .departmentId("infra")
            .build();

        Map<String, Object> baseMap = Map.of("key1", "val1");
        Map<String, Object> packedMap = SecurityInvocationParameters.withIdentity(baseMap, identity);

        assertThat(packedMap).containsKey("key1");
        assertThat(packedMap).containsKey(SecurityInvocationParameters.KEY_IDENTITY);

        Optional<SecurityIdentity> extracted = SecurityInvocationParameters.extractIdentity(packedMap);
        assertThat(extracted).isPresent().contains(identity);

        assertThat(SecurityInvocationParameters.getTenantId(packedMap)).contains("tenant-map");
        assertThat(SecurityInvocationParameters.getSubjectId(packedMap)).contains("sub-map");
        assertThat(SecurityInvocationParameters.getRoles(packedMap)).contains(Set.of("ROLE_ENGINEER"));
        assertThat(SecurityInvocationParameters.getClearanceFloor(packedMap)).contains(1);
        assertThat(SecurityInvocationParameters.getDepartmentId(packedMap)).contains("infra");
    }

    @Test
    @DisplayName("Fallback behavior: Reconstructs SecurityIdentity when sec:identity is absent but individual keys are present")
    void testFallbackExtractionFromIndividualKeys() {
        Map<String, Object> map = new HashMap<>();
        map.put(SecurityInvocationParameters.KEY_SUBJECT_ID, "reconstructed-user");
        map.put(SecurityInvocationParameters.KEY_TENANT_ID, "reconstructed-tenant");
        map.put(SecurityInvocationParameters.KEY_ROLES, List.of("ROLE_DEVOPS", "ROLE_ADMIN"));
        map.put(SecurityInvocationParameters.KEY_CLEARANCE_FLOOR, 3);
        map.put(SecurityInvocationParameters.KEY_DEPARTMENT_ID, "platform");

        InvocationParameters params = InvocationParameters.from(map);

        Optional<SecurityIdentity> extracted = SecurityInvocationParameters.extractIdentity(params);
        assertThat(extracted).isPresent();
        SecurityIdentity identity = extracted.get();

        assertThat(identity.subjectId()).isEqualTo("reconstructed-user");
        assertThat(identity.tenantId()).isEqualTo("reconstructed-tenant");
        assertThat(identity.roles()).containsExactlyInAnyOrder("ROLE_DEVOPS", "ROLE_ADMIN");
        assertThat(identity.clearanceFloor()).isEqualTo(3);
        assertThat(identity.departmentId()).isEqualTo("platform");
    }

    @Test
    @DisplayName("Fallback behavior: Fails closed (empty) if subjectId or tenantId is missing or blank")
    void testFallbackFailsClosedWhenSubjectOrTenantMissing() {
        // Missing subjectId
        Map<String, Object> missingSubject = Map.of(
            SecurityInvocationParameters.KEY_TENANT_ID, "tenant-1",
            SecurityInvocationParameters.KEY_CLEARANCE_FLOOR, 1
        );
        assertThat(SecurityInvocationParameters.extractIdentity(missingSubject)).isEmpty();

        // Missing tenantId
        Map<String, Object> missingTenant = Map.of(
            SecurityInvocationParameters.KEY_SUBJECT_ID, "user-1",
            SecurityInvocationParameters.KEY_CLEARANCE_FLOOR, 1
        );
        assertThat(SecurityInvocationParameters.extractIdentity(missingTenant)).isEmpty();

        // Blank subjectId
        Map<String, Object> blankSubject = Map.of(
            SecurityInvocationParameters.KEY_SUBJECT_ID, "   ",
            SecurityInvocationParameters.KEY_TENANT_ID, "tenant-1"
        );
        assertThat(SecurityInvocationParameters.extractIdentity(blankSubject)).isEmpty();
    }

    @Test
    @DisplayName("Passing null parameters or maps returns Optional.empty() safely")
    void testNullHandling() {
        assertThat(SecurityInvocationParameters.extractIdentity((InvocationParameters) null)).isEmpty();
        assertThat(SecurityInvocationParameters.extractIdentity((Map<String, Object>) null)).isEmpty();
        assertThat(SecurityInvocationParameters.extractIdentity((Query) null)).isEmpty();

        assertThat(SecurityInvocationParameters.getTenantId((InvocationParameters) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getTenantId((Map<String, Object>) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getSubjectId((InvocationParameters) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getSubjectId((Map<String, Object>) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getRoles((InvocationParameters) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getRoles((Map<String, Object>) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getClearanceFloor((InvocationParameters) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getClearanceFloor((Map<String, Object>) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getDepartmentId((InvocationParameters) null)).isEmpty();
        assertThat(SecurityInvocationParameters.getDepartmentId((Map<String, Object>) null)).isEmpty();
    }

    @Test
    @DisplayName("withIdentity throws NullPointerException if identity is null")
    void testWithIdentityNullCheck() {
        assertThatThrownBy(() -> SecurityInvocationParameters.withIdentity((InvocationParameters) null, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("identity must not be null");

        assertThatThrownBy(() -> SecurityInvocationParameters.withIdentity((Map<String, Object>) null, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("identity must not be null");
    }

    @Test
    @DisplayName("withIdentity handles null existing parameters gracefully")
    void testWithIdentityNullExisting() {
        SecurityIdentity identity = SecurityIdentity.anonymous("tenant-test");
        InvocationParameters params = SecurityInvocationParameters.withIdentity((InvocationParameters) null, identity);

        assertThat(params).isNotNull();
        assertThat(SecurityInvocationParameters.extractIdentity(params)).contains(identity);
    }
}
