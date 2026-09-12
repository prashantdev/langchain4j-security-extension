package dev.langchain4j.security.agent;

import dev.langchain4j.security.context.SecurityIdentity;

/**
 * Thrown when caller fails authorization at the agent invocation boundary.
 */
public class AgentSecurityException extends RuntimeException {

    private final SecurityIdentity identity;
    private final String reasonCode;

    public AgentSecurityException(String message, SecurityIdentity identity, String reasonCode) {
        super(message);
        this.identity = identity;
        this.reasonCode = reasonCode;
    }

    public SecurityIdentity getIdentity() {
        return identity;
    }

    public String getReasonCode() {
        return reasonCode;
    }
}
