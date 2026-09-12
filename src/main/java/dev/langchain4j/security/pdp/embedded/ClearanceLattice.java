package dev.langchain4j.security.pdp.embedded;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Compares numeric classification and clearance levels: PUBLIC (0) to RESTRICTED (3).
 */
public class ClearanceLattice {

    public static final int PUBLIC = 0;
    public static final int INTERNAL = 1;
    public static final int CONFIDENTIAL = 2;
    public static final int RESTRICTED = 3;

    private final Map<String, Integer> labelToRank = new HashMap<>();

    public ClearanceLattice() {
        labelToRank.put("PUBLIC", PUBLIC);
        labelToRank.put("INTERNAL", INTERNAL);
        labelToRank.put("CONFIDENTIAL", CONFIDENTIAL);
        labelToRank.put("RESTRICTED", RESTRICTED);
    }

    public synchronized void registerLevel(String label, int rank) {
        Objects.requireNonNull(label, "label must not be null");
        labelToRank.put(label.trim().toUpperCase(), rank);
    }

    public int parseLevel(String label) {
        if (label == null || label.isBlank()) {
            return PUBLIC;
        }
        return labelToRank.getOrDefault(label.trim().toUpperCase(), PUBLIC);
    }

    public boolean satisfies(int callerClearance, int requiredClearance) {
        return callerClearance >= requiredClearance;
    }
}
