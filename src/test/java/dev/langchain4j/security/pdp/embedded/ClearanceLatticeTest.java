package dev.langchain4j.security.pdp.embedded;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ClearanceLatticeTest {

    @Test
    @DisplayName("Should enforce standard clearance ranks: PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED")
    void testStandardClearanceHierarchy() {
        ClearanceLattice lattice = new ClearanceLattice();

        assertThat(lattice.parseLevel("PUBLIC")).isEqualTo(ClearanceLattice.PUBLIC);
        assertThat(lattice.parseLevel("INTERNAL")).isEqualTo(ClearanceLattice.INTERNAL);
        assertThat(lattice.parseLevel("CONFIDENTIAL")).isEqualTo(ClearanceLattice.CONFIDENTIAL);
        assertThat(lattice.parseLevel("RESTRICTED")).isEqualTo(ClearanceLattice.RESTRICTED);

        assertThat(lattice.satisfies(ClearanceLattice.CONFIDENTIAL, ClearanceLattice.INTERNAL)).isTrue();
        assertThat(lattice.satisfies(ClearanceLattice.CONFIDENTIAL, ClearanceLattice.CONFIDENTIAL)).isTrue();
        assertThat(lattice.satisfies(ClearanceLattice.INTERNAL, ClearanceLattice.CONFIDENTIAL)).isFalse();
        assertThat(lattice.satisfies(ClearanceLattice.PUBLIC, ClearanceLattice.RESTRICTED)).isFalse();
    }

    @Test
    @DisplayName("Should support custom level registration and case insensitivity")
    void testCustomLevelRegistration() {
        ClearanceLattice lattice = new ClearanceLattice();
        lattice.registerLevel("SECRET", 4);
        lattice.registerLevel("TOP_SECRET", 5);

        assertThat(lattice.parseLevel("secret")).isEqualTo(4);
        assertThat(lattice.parseLevel("TOP_SECRET")).isEqualTo(5);
        assertThat(lattice.satisfies(5, 4)).isTrue();
        assertThat(lattice.satisfies(4, 5)).isFalse();
    }

    @Test
    @DisplayName("Should handle unknown and null levels gracefully with fallback to PUBLIC")
    void testNullAndUnknownLevels() {
        ClearanceLattice lattice = new ClearanceLattice();
        assertThat(lattice.parseLevel(null)).isEqualTo(ClearanceLattice.PUBLIC);
        assertThat(lattice.parseLevel("")).isEqualTo(ClearanceLattice.PUBLIC);
        assertThat(lattice.parseLevel("UNKNOWN_TIER")).isEqualTo(ClearanceLattice.PUBLIC);
    }

    @Test
    @DisplayName("Should handle boundary values correctly")
    void testBoundaryValues() {
        ClearanceLattice lattice = new ClearanceLattice();
        assertThat(lattice.satisfies(0, 0)).isTrue();
        assertThat(lattice.satisfies(-1, 0)).isFalse();
        assertThat(lattice.satisfies(Integer.MAX_VALUE, 100)).isTrue();
        assertThat(lattice.satisfies(100, Integer.MAX_VALUE)).isFalse();
    }
}
