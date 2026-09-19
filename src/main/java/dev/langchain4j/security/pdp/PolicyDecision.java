package dev.langchain4j.security.pdp;

/**
 * Canonical access authorization decision outcomes.
 */
public enum PolicyDecision {
    /** Access explicitly permitted. */
    PERMIT,

    /** Access explicitly denied. */
    DENY,

    /** No matching policy rule applied. */
    NOT_APPLICABLE,

    /** Policy evaluation resulted in error or indeterminate state. */
    INDETERMINATE;

    /**
     * Checks if this decision is PERMIT.
     *
     * @return true if PERMIT, false otherwise
     */
    public boolean isPermitted() {
        return this == PERMIT;
    }

    /**
     * Checks if this decision is DENY.
     *
     * @return true if DENY, false otherwise
     */
    public boolean isDenied() {
        return this == DENY;
    }
}
