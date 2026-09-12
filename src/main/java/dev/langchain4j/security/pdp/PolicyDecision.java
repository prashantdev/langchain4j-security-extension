package dev.langchain4j.security.pdp;

/**
 * Canonical access authorization decision outcomes.
 */
public enum PolicyDecision {
    PERMIT,
    DENY,
    NOT_APPLICABLE,
    INDETERMINATE;

    public boolean isPermitted() {
        return this == PERMIT;
    }

    public boolean isDenied() {
        return this == DENY;
    }
}
