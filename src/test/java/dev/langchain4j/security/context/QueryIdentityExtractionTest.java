package dev.langchain4j.security.context;

import dev.langchain4j.invocation.InvocationParameters;
import dev.langchain4j.rag.query.Metadata;
import dev.langchain4j.rag.query.Query;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class QueryIdentityExtractionTest {

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clear();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clear();
    }

    @Test
    @DisplayName("Extract identity from Query metadata invocationParameters")
    void testExtractIdentityFromQueryMetadataInvocationParameters() {
        SecurityIdentity expectedIdentity = SecurityIdentity.builder()
            .subjectId("user-100")
            .tenantId("tenant-beta")
            .addRole("ANALYST")
            .clearanceFloor(2)
            .departmentId("FINANCE")
            .build();

        InvocationParameters nativeParams = InvocationParameters.from(
            SecurityInvocationParameters.withIdentity((dev.langchain4j.security.context.InvocationParameters) null, expectedIdentity).asMap()
        );

        dev.langchain4j.invocation.InvocationContext invocationContext = dev.langchain4j.invocation.InvocationContext.builder()
            .invocationParameters(nativeParams)
            .build();

        Metadata metadata = Metadata.builder()
            .chatMessage(dev.langchain4j.data.message.UserMessage.from("What is Q3 revenue?"))
            .invocationContext(invocationContext)
            .build();

        Query query = Query.from("What is Q3 revenue?", metadata);

        Optional<SecurityIdentity> extracted = SecurityInvocationParameters.extractIdentity(query);

        assertThat(extracted).isPresent();
        assertThat(extracted.get().subjectId()).isEqualTo("user-100");
        assertThat(extracted.get().tenantId()).isEqualTo("tenant-beta");
        assertThat(extracted.get().roles()).contains("ANALYST");
    }

    @Test
    @DisplayName("Extract identity from ambient SecurityContextHolder when Query metadata lacks identity")
    void testExtractIdentityFromAmbientSecurityContextHolder() {
        SecurityIdentity ambientIdentity = SecurityIdentity.builder()
            .subjectId("ambient-user")
            .tenantId("tenant-gamma")
            .addRole("ENGINEER")
            .clearanceFloor(1)
            .build();

        SecurityContextHolder.setIdentity(ambientIdentity);

        Query plainQuery = Query.from("System architecture overview");

        Optional<SecurityIdentity> extracted = SecurityInvocationParameters.extractIdentity(plainQuery);

        assertThat(extracted).isPresent();
        assertThat(extracted.get().subjectId()).isEqualTo("ambient-user");
        assertThat(extracted.get().tenantId()).isEqualTo("tenant-gamma");
    }
}
