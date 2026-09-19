package dev.langchain4j.security.agent;

import dev.langchain4j.security.context.SecurityIdentity;

/**
 * Thrown when caller fails authorization at the agent invocation boundary.
 */
public class AgentSecurityException extends RuntimeException {

    /** Security identity of the caller. */
    private final SecurityIdentity identity;

    /** Reason code for the security exception. */
    private final String reasonCode;

    /**
     * Constructs a new AgentSecurityException.
     *
     * @param message the detailed error message
     * @param identity the security identity of the caller
     * @param reasonCode the security reason code for the violation
     */
    public AgentSecurityException(String message, SecurityIdentity identity, String reasonCode) {
        super(message);
        this.identity = identity;
        this.reasonCode = reasonCode;
    }

    /**
     * Returns the security identity of the caller associated with this exception.
     *
     * @return the caller's security identity
     */
    public SecurityIdentity getIdentity() {
        return identity;
    }

    /**
     * Returns the reason code explaining why authorization was denied.
     *
     * @return the security reason code
     */
    public String getReasonCode() {
        return reasonCode;
    }
}
