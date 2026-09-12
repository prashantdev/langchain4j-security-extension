package dev.langchain4j.security.context;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityIdentityTest {

    @Test
    @DisplayName("Builder creates SecurityIdentity with all properties properly populated")
    void testBuilderCreationAndProperties() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user-123")
            .tenantId("tenant-abc")
            .roles(Set.of("ROLE_USER", "ROLE_ANALYST"))
            .clearanceFloor(2)
            .departmentId("finance")
            .addAttribute("email", "user123@example.com")
            .addAttribute("costCenter", 4001)
            .build();

        assertThat(identity.subjectId()).isEqualTo("user-123");
        assertThat(identity.tenantId()).isEqualTo("tenant-abc");
        assertThat(identity.roles()).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ANALYST");
        assertThat(identity.clearanceFloor()).isEqualTo(2);
        assertThat(identity.departmentId()).isEqualTo("finance");
        assertThat(identity.attributes()).containsEntry("email", "user123@example.com");
        assertThat(identity.attributes()).containsEntry("costCenter", 4001);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("Null or blank subjectId throws IllegalArgumentException")
    void testNullOrBlankSubjectThrowsIllegalArgument(String invalidSubjectId) {
        assertThatThrownBy(() -> SecurityIdentity.builder()
            .subjectId(invalidSubjectId)
            .tenantId("tenant-1")
            .build()
        ).isInstanceOf(IllegalArgumentException.class)
         .hasMessageContaining("subjectId must not be null or blank");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t", "\n"})
    @DisplayName("Null or blank tenantId throws IllegalArgumentException")
    void testNullOrBlankTenantThrowsIllegalArgument(String invalidTenantId) {
        assertThatThrownBy(() -> SecurityIdentity.builder()
            .subjectId("user-1")
            .tenantId(invalidTenantId)
            .build()
        ).isInstanceOf(IllegalArgumentException.class)
         .hasMessageContaining("tenantId must not be null or blank");
    }

    @Test
    @DisplayName("AC 1.1: Mutating source roles set does not mutate internal record state")
    void testImmutabilityAndDefensiveCopiesForRoles() {
        Set<String> mutableRoles = new HashSet<>();
        mutableRoles.add("ROLE_USER");
        mutableRoles.add("ROLE_OPS");

        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user-1")
            .tenantId("tenant-1")
            .roles(mutableRoles)
            .build();

        // Mutate original set
        mutableRoles.add("ROLE_SUPERUSER");
        assertThat(identity.roles()).doesNotContain("ROLE_SUPERUSER");
        assertThat(identity.hasRole("ROLE_SUPERUSER")).isFalse();

        // Attempt mutating returned set directly
        assertThatThrownBy(() -> identity.roles().add("ROLE_ESCALATED"))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("AC 1.1: Mutating source attributes map does not mutate internal record state")
    void testImmutabilityAndDefensiveCopiesForAttributes() {
        Map<String, Object> mutableAttrs = new HashMap<>();
        mutableAttrs.put("env", "staging");
        mutableAttrs.put("level", 1);

        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user-1")
            .tenantId("tenant-1")
            .attributes(mutableAttrs)
            .build();

        // Mutate original map
        mutableAttrs.put("env", "production");
        mutableAttrs.put("extra", "hacked");

        assertThat(identity.attributes().get("env")).isEqualTo("staging");
        assertThat(identity.attributes()).doesNotContainKey("extra");

        // Attempt mutating returned attributes map directly
        assertThatThrownBy(() -> identity.attributes().put("foo", "bar"))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Null roles and attributes collections default gracefully to empty collections")
    void testNullRolesAndAttributesDefaultGracefully() {
        SecurityIdentity identity = new SecurityIdentity(
            "user-1", "tenant-1", null, 0, null, null
        );

        assertThat(identity.roles()).isNotNull().isEmpty();
        assertThat(identity.attributes()).isNotNull().isEmpty();
        assertThat(identity.departmentId()).isNull();
        assertThat(identity.clearanceFloor()).isEqualTo(0);
    }

    @Test
    @DisplayName("Null role strings or blank roles added to builder are safely ignored")
    void testBuilderIgnoresNullOrBlankRoles() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user-1")
            .tenantId("tenant-1")
            .addRole(null)
            .addRole("")
            .addRole("   ")
            .addRole("ROLE_VALID")
            .build();

        assertThat(identity.roles()).containsExactly("ROLE_VALID");
    }

    @Test
    @DisplayName("hasRole returns true for assigned roles and false for absent or null roles")
    void testHasRole() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user-1")
            .tenantId("tenant-1")
            .addRole("ROLE_DEV")
            .build();

        assertThat(identity.hasRole("ROLE_DEV")).isTrue();
        assertThat(identity.hasRole("ROLE_ADMIN")).isFalse();
        assertThat(identity.hasRole(null)).isFalse();
    }

    @Test
    @DisplayName("satisfiesClearance evaluates numeric clearance floor correctly")
    void testSatisfiesClearance() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user-1")
            .tenantId("tenant-1")
            .clearanceFloor(2)
            .build();

        assertThat(identity.satisfiesClearance(0)).isTrue();
        assertThat(identity.satisfiesClearance(1)).isTrue();
        assertThat(identity.satisfiesClearance(2)).isTrue();
        assertThat(identity.satisfiesClearance(3)).isFalse();
    }

    @Test
    @DisplayName("getAttribute and type-safe getAttribute retrieve attribute values safely")
    void testGetAttributeAndTypeSafeRetrieval() {
        SecurityIdentity identity = SecurityIdentity.builder()
            .subjectId("user-1")
            .tenantId("tenant-1")
            .addAttribute("timeout", 5000)
            .addAttribute("zone", "us-east-1")
            .build();

        assertThat(identity.getAttribute("zone")).contains("us-east-1");
        assertThat(identity.getAttribute("missing")).isEmpty();
        assertThat(identity.getAttribute(null)).isEmpty();

        assertThat(identity.getAttribute("timeout", Integer.class)).contains(5000);
        assertThat(identity.getAttribute("timeout", String.class)).isEmpty();
        assertThat(identity.getAttribute("zone", String.class)).contains("us-east-1");
        assertThat(identity.getAttribute("missing", String.class)).isEmpty();
        assertThat(identity.getAttribute(null, String.class)).isEmpty();
        assertThat(identity.getAttribute("timeout", null)).isEmpty();
    }

    @Test
    @DisplayName("anonymous factory creates standard anonymous caller identity")
    void testAnonymousIdentityFactory() {
        SecurityIdentity anonymous = SecurityIdentity.anonymous("tenant-omega");

        assertThat(anonymous.subjectId()).isEqualTo(SecurityIdentity.ANONYMOUS_SUBJECT);
        assertThat(anonymous.tenantId()).isEqualTo("tenant-omega");
        assertThat(anonymous.clearanceFloor()).isEqualTo(SecurityIdentity.DEFAULT_CLEARANCE);
        assertThat(anonymous.roles()).containsExactly("ANONYMOUS");
        assertThat(anonymous.hasRole("ANONYMOUS")).isTrue();
    }

    @Test
    @DisplayName("SecurityIdentity supports Java Serialization round-trip")
    void testSerializationRoundTrip() throws Exception {
        SecurityIdentity original = SecurityIdentity.builder()
            .subjectId("ser-user")
            .tenantId("ser-tenant")
            .addRole("ROLE_A")
            .addRole("ROLE_B")
            .clearanceFloor(3)
            .departmentId("security")
            .addAttribute("tag", "serialized")
            .build();

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(original);
        }

        ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
        SecurityIdentity deserialized;
        try (ObjectInputStream ois = new ObjectInputStream(bais)) {
            deserialized = (SecurityIdentity) ois.readObject();
        }

        assertThat(deserialized).isEqualTo(original);
        assertThat(deserialized.roles()).containsExactlyInAnyOrder("ROLE_A", "ROLE_B");
        assertThat(deserialized.attributes()).containsEntry("tag", "serialized");
    }
}
