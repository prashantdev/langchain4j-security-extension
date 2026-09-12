package dev.langchain4j.security.adversarial;

import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.embedded.ClearanceLattice;
import dev.langchain4j.security.pdp.embedded.EmbeddedInMemoryPdp;
import dev.langchain4j.security.retrieval.SecureContentRetriever;
import dev.langchain4j.security.retrieval.SecurityMetadataNamespaces;
import dev.langchain4j.security.tool.HardAbortToolExecutionInterceptor;
import dev.langchain4j.security.tool.ToolExecutionDeniedException;
import dev.langchain4j.security.tool.annotation.SecuredTool;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("Adversarial Test Suite: Clearance Lattice & Classification Edge Conditions")
class ClearanceLatticeAdversarialTest {

    interface ClassifiedIntelligenceTool {
        @SecuredTool(minClearance = ClearanceLattice.RESTRICTED, requiredTenant = "INTEL_AGENCY")
        String readTopSecretFile(String fileId);
    }

    static class ClassifiedIntelligenceToolImpl implements ClassifiedIntelligenceTool {
        @Override
        public String readTopSecretFile(String fileId) {
            return "CONTENT_OF_" + fileId;
        }
    }

    @Test
    @DisplayName("Tool PEP: Lower clearance callers (0, 1, 2) are blocked from RESTRICTED (3) tool")
    void testClearanceFloorViolationsBlocked() {
        EmbeddedInMemoryPdp pdp = new EmbeddedInMemoryPdp();
        ClassifiedIntelligenceTool rawTool = new ClassifiedIntelligenceToolImpl();

        int[] insufficientClearances = {ClearanceLattice.PUBLIC, ClearanceLattice.INTERNAL, ClearanceLattice.CONFIDENTIAL, -1};

        for (int clearance : insufficientClearances) {
            SecurityIdentity caller = SecurityIdentity.builder()
                .subjectId("analyst_" + clearance)
                .tenantId("INTEL_AGENCY")
                .clearanceFloor(clearance)
                .build();

            ClassifiedIntelligenceTool proxy = (ClassifiedIntelligenceTool) HardAbortToolExecutionInterceptor.wrap(
                rawTool, pdp, null, () -> caller
            );

            assertThatThrownBy(() -> proxy.readTopSecretFile("doc-001"))
                .isInstanceOf(ToolExecutionDeniedException.class)
                .satisfies(ex -> {
                    ToolExecutionDeniedException tede = (ToolExecutionDeniedException) ex;
                    assertThat(tede.getReasonCode()).isEqualTo("TOOL_EXECUTION_DENIED");
                });
        }

        // Caller with clearance 3 (RESTRICTED) should be permitted
        SecurityIdentity topSecretCaller = SecurityIdentity.builder()
            .subjectId("director")
            .tenantId("INTEL_AGENCY")
            .clearanceFloor(ClearanceLattice.RESTRICTED)
            .build();

        ClassifiedIntelligenceTool authorizedProxy = (ClassifiedIntelligenceTool) HardAbortToolExecutionInterceptor.wrap(
            rawTool, pdp, null, () -> topSecretCaller
        );

        assertThat(authorizedProxy.readTopSecretFile("doc-001")).isEqualTo("CONTENT_OF_doc-001");
    }

    @Test
    @DisplayName("Retrieval Post-Pruning: Chunks exceeding caller clearance are pruned regardless of data format")
    void testRetrievalPruningByClearanceFloor() {
        ContentRetriever mockRetriever = mock(ContentRetriever.class);

        SecurityIdentity confidentialCaller = SecurityIdentity.builder()
            .subjectId("agent_006")
            .tenantId("AGENCY")
            .clearanceFloor(ClearanceLattice.CONFIDENTIAL) // clearance = 2
            .build();

        // Chunks with various clearance representations
        Content publicChunk = Content.from(TextSegment.from("Public intel",
            Metadata.from(Map.of(
                SecurityMetadataNamespaces.TENANT_ID, "AGENCY",
                SecurityMetadataNamespaces.CLEARANCE_FLOOR, ClearanceLattice.PUBLIC
            ))));

        Content internalChunk = Content.from(TextSegment.from("Internal intel",
            Metadata.from(Map.of(
                SecurityMetadataNamespaces.TENANT_ID, "AGENCY",
                SecurityMetadataNamespaces.CLEARANCE_FLOOR, "1" // String representation
            ))));

        Content confidentialChunk = Content.from(TextSegment.from("Confidential intel",
            Metadata.from(Map.of(
                SecurityMetadataNamespaces.TENANT_ID, "AGENCY",
                SecurityMetadataNamespaces.CLEARANCE_FLOOR, 2
            ))));

        Content restrictedChunkNum = Content.from(TextSegment.from("Restricted intel (int)",
            Metadata.from(Map.of(
                SecurityMetadataNamespaces.TENANT_ID, "AGENCY",
                SecurityMetadataNamespaces.CLEARANCE_FLOOR, 3
            ))));

        Content restrictedChunkStr = Content.from(TextSegment.from("Restricted intel (str)",
            Metadata.from(Map.of(
                SecurityMetadataNamespaces.TENANT_ID, "AGENCY",
                SecurityMetadataNamespaces.CLEARANCE_FLOOR, " 3 "
            ))));

        when(mockRetriever.retrieve(any(Query.class)))
            .thenReturn(List.of(publicChunk, internalChunk, confidentialChunk, restrictedChunkNum, restrictedChunkStr));

        SecureContentRetriever secureRetriever = SecureContentRetriever.builder()
            .contentRetriever(mockRetriever)
            .identitySupplier(() -> confidentialCaller)
            .build();

        List<Content> results = secureRetriever.retrieve(Query.from("give me intel"));

        // Only chunks with clearance <= 2 should be returned
        assertThat(results).hasSize(3);
        assertThat(results).extracting(c -> c.textSegment().text())
            .containsExactlyInAnyOrder("Public intel", "Internal intel", "Confidential intel");
    }

    @Test
    @DisplayName("Lattice Edge Conditions: Custom clearance registration and boundary checks")
    void testClearanceLatticeCustomLevelsAndBoundaries() {
        ClearanceLattice lattice = new ClearanceLattice();

        // Test standard ranks
        assertThat(lattice.parseLevel("PUBLIC")).isEqualTo(0);
        assertThat(lattice.parseLevel("INTERNAL")).isEqualTo(1);
        assertThat(lattice.parseLevel("CONFIDENTIAL")).isEqualTo(2);
        assertThat(lattice.parseLevel("RESTRICTED")).isEqualTo(3);

        // Unknown level defaults to PUBLIC (0)
        assertThat(lattice.parseLevel("UNKNOWN_LEVEL")).isEqualTo(0);
        assertThat(lattice.parseLevel(null)).isEqualTo(0);
        assertThat(lattice.parseLevel("   ")).isEqualTo(0);

        // Custom registration
        lattice.registerLevel("SECRET_COMPARTMENT", 10);
        lattice.registerLevel("TOP_SECRET_SCI", 20);

        assertThat(lattice.parseLevel("secret_compartment")).isEqualTo(10);
        assertThat(lattice.parseLevel("TOP_SECRET_SCI")).isEqualTo(20);

        assertThat(lattice.satisfies(20, 10)).isTrue();
        assertThat(lattice.satisfies(10, 20)).isFalse();
        assertThat(lattice.satisfies(0, 1)).isFalse();
        assertThat(lattice.satisfies(-1, 0)).isFalse();
        assertThat(lattice.satisfies(Integer.MAX_VALUE, 20)).isTrue();
    }
}
