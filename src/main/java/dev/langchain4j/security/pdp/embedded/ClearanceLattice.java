package dev.langchain4j.security.pdp.embedded;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Compares numeric classification and clearance levels: PUBLIC (0) to RESTRICTED (3).
 */
public class ClearanceLattice {

    /** Public clearance level constant (rank 0). */
    public static final int PUBLIC = 0;

    /** Internal clearance level constant (rank 1). */
    public static final int INTERNAL = 1;

    /** Confidential clearance level constant (rank 2). */
    public static final int CONFIDENTIAL = 2;

    /** Restricted clearance level constant (rank 3). */
    public static final int RESTRICTED = 3;

    private final Map<String, Integer> labelToRank = new HashMap<>();

    /**
     * Constructs a new ClearanceLattice with default clearance levels registered.
     */
    public ClearanceLattice() {
        labelToRank.put("PUBLIC", PUBLIC);
        labelToRank.put("INTERNAL", INTERNAL);
        labelToRank.put("CONFIDENTIAL", CONFIDENTIAL);
        labelToRank.put("RESTRICTED", RESTRICTED);
    }

    /**
     * Registers a custom clearance level label and rank.
     *
     * @param label clearance level label
     * @param rank clearance level rank
     */
    public synchronized void registerLevel(String label, int rank) {
        Objects.requireNonNull(label, "label must not be null");
        labelToRank.put(label.trim().toUpperCase(), rank);
    }

    /**
     * Parses a clearance label string to its integer rank.
     *
     * @param label clearance label string
     * @return integer rank value, defaulting to PUBLIC (0) if unknown or blank
     */
    public int parseLevel(String label) {
        if (label == null || label.isBlank()) {
            return PUBLIC;
        }
        return labelToRank.getOrDefault(label.trim().toUpperCase(), PUBLIC);
    }

    /**
     * Evaluates whether caller clearance satisfies the required clearance rank.
     *
     * @param callerClearance caller clearance rank
     * @param requiredClearance required clearance rank
     * @return true if caller clearance >= required clearance, false otherwise
     */
    public boolean satisfies(int callerClearance, int requiredClearance) {
        return callerClearance >= requiredClearance;
    }
}
