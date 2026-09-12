package dev.langchain4j.security.pdp;

/**
 * Service Provider Interface for authorizing action requests against defined policies.
 */
@FunctionalInterface
public interface PolicyDecisionEngine {

    /**
     * Evaluates a policy evaluation request and returns the resulting decision.
     *
     * @param request the policy evaluation request
     * @return the authorization decision outcome
     */
    PolicyDecision evaluate(PolicyEvaluationRequest request);
}
