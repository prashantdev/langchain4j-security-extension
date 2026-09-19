package dev.langchain4j.security.agent;

import dev.langchain4j.security.agent.annotation.SecuredAgent;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.InvocationParameters;
import dev.langchain4j.security.context.SecurityContextHolder;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.context.SecurityInvocationParameters;
import dev.langchain4j.security.pdp.PolicyDecision;
import dev.langchain4j.security.pdp.PolicyDecisionEngine;
import dev.langchain4j.security.pdp.PolicyEvaluationRequest;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

/**
 * Intercepts calls to an AI Service interface before prompting the model.
 */
public class AgentSecurityInvocationHandler implements InvocationHandler {

    private final Object target;
    private final Class<?> interfaceClass;
    private final PolicyDecisionEngine pdp;
    private final SecurityAuditPublisher auditPublisher;
    private final SecurityIdentity boundIdentity;

    /**
     * Constructs an AgentSecurityInvocationHandler.
     *
     * @param target the target object to proxy
     * @param interfaceClass the AI service interface class
     * @param pdp the policy decision engine to evaluate access requests
     * @param auditPublisher the publisher for security audit events
     * @param boundIdentity the security identity explicitly bound to this invocation handler, or null
     */
    public AgentSecurityInvocationHandler(
        Object target,
        Class<?> interfaceClass,
        PolicyDecisionEngine pdp,
        SecurityAuditPublisher auditPublisher,
        SecurityIdentity boundIdentity
    ) {
        this.target = Objects.requireNonNull(target, "target must not be null");
        this.interfaceClass = Objects.requireNonNull(interfaceClass, "interfaceClass must not be null");
        this.pdp = Objects.requireNonNull(pdp, "pdp must not be null");
        this.auditPublisher = (auditPublisher == null) ? SecurityAuditPublisher.noop() : auditPublisher;
        this.boundIdentity = boundIdentity;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getDeclaringClass() == Object.class) {
            return method.invoke(target, args);
        }

        // 1. Resolve security metadata (method level overrides class level)
        SecuredAgent annotation = method.getAnnotation(SecuredAgent.class);
        if (annotation == null) {
            annotation = interfaceClass.getAnnotation(SecuredAgent.class);
        }

        // 2. Resolve caller identity
        SecurityIdentity caller = resolveCallerIdentity(args);

        // Fail-closed for unauthenticated caller on secured agent
        if (caller == null) {
            publishAudit(null, method, PolicyDecision.DENY, "UNAUTHENTICATED_CALLER");
            throw new AgentSecurityException(
                "Access denied: Unauthenticated invocation on secured agent interface " + interfaceClass.getSimpleName(),
                null,
                "UNAUTHENTICATED_CALLER"
            );
        }

        // 3. Evaluate security policy if annotated
        if (annotation != null) {
            PolicyEvaluationRequest request = PolicyEvaluationRequest.builder()
                .subject(caller)
                .action("agent:invoke")
                .resource(interfaceClass.getName() + "#" + method.getName())
                .context(Map.of(
                    "requiredRoles", Set.of(annotation.requiredRoles()),
                    "minClearance", annotation.minClearance(),
                    "requiredTenant", annotation.requiredTenant()
                ))
                .build();

            PolicyDecision decision = pdp.evaluate(request);

            if (decision != PolicyDecision.PERMIT) {
                publishAudit(caller, method, decision, "AGENT_AUTHORIZATION_FAILED");
                throw new AgentSecurityException(
                    String.format("Access denied: Caller '%s' not authorized to invoke '%s#%s'. Decision: %s",
                        caller.subjectId(), interfaceClass.getSimpleName(), method.getName(), decision),
                    caller,
                    "AGENT_AUTHORIZATION_FAILED"
                );
            }

            publishAudit(caller, method, PolicyDecision.PERMIT, "AGENT_ACCESS_PERMITTED");
        }

        try {
            method.setAccessible(true);
            return SecurityContextHolder.runWithIdentity(caller, (java.util.function.Supplier<Object>) () -> {
                try {
                    return method.invoke(target, args);
                } catch (InvocationTargetException e) {
                    throw new WrappedInvocationException(e.getCause());
                } catch (IllegalAccessException e) {
                    throw new RuntimeException(e);
                }
            });
        } catch (WrappedInvocationException e) {
            throw e.getCause();
        }
    }

    private SecurityIdentity resolveCallerIdentity(Object[] args) {
        if (args != null) {
            for (Object arg : args) {
                if (arg instanceof SecurityIdentity si) {
                    return si;
                }
                if (arg instanceof InvocationParameters ip) {
                    Optional<SecurityIdentity> extracted = SecurityInvocationParameters.extractIdentity(ip);
                    if (extracted.isPresent()) {
                        return extracted.get();
                    }
                }
            }
        }
        return boundIdentity;
    }

    private void publishAudit(SecurityIdentity id, Method m, PolicyDecision decision, String reason) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
            .subjectId(id == null ? "UNAUTHENTICATED" : id.subjectId())
            .tenantId(id == null ? "UNKNOWN" : id.tenantId())
            .subjectRoles(id == null ? Set.of() : id.roles())
            .subjectClearance(id == null ? 0 : id.clearanceFloor())
            .enforcementPoint("AGENT_GUARD")
            .action("agent:invoke")
            .targetResource(interfaceClass.getSimpleName() + "#" + m.getName())
            .decision(decision == PolicyDecision.PERMIT ? "ALLOW" : "DENY")
            .reasonCode(reason)
            .severity(decision == PolicyDecision.PERMIT ? "INFORMATIONAL" : "SECURITY_ALERT")
            .build();
        auditPublisher.publish(event);
    }

    private static class WrappedInvocationException extends RuntimeException {
        private final Throwable cause;

        public WrappedInvocationException(Throwable cause) {
            super(cause);
            this.cause = cause;
        }

        @Override
        public Throwable getCause() {
            return cause;
        }
    }
}
