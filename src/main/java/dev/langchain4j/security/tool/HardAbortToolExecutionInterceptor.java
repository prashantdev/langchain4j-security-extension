package dev.langchain4j.security.tool;

import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.PolicyDecision;
import dev.langchain4j.security.pdp.PolicyDecisionEngine;
import dev.langchain4j.security.pdp.PolicyEvaluationRequest;
import dev.langchain4j.security.tool.annotation.SecuredTool;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Proxy;
import java.util.*;
import java.util.function.Supplier;

/**
 * Enforces strict PEP checks prior to tool method invocation.
 * On violation, throws {@link ToolExecutionDeniedException} to halt execution immediately.
 */
public class HardAbortToolExecutionInterceptor implements InvocationHandler {

    private final Object targetTool;
    private final PolicyDecisionEngine pdp;
    private final SecurityAuditPublisher auditPublisher;
    private final Supplier<SecurityIdentity> identitySupplier;

    /**
     * Constructs a HardAbortToolExecutionInterceptor.
     *
     * @param targetTool target tool object instance
     * @param pdp PolicyDecisionEngine instance
     * @param auditPublisher SecurityAuditPublisher instance
     * @param identitySupplier Supplier returning current caller SecurityIdentity
     */
    public HardAbortToolExecutionInterceptor(
        Object targetTool,
        PolicyDecisionEngine pdp,
        SecurityAuditPublisher auditPublisher,
        Supplier<SecurityIdentity> identitySupplier
    ) {
        this.targetTool = Objects.requireNonNull(targetTool, "targetTool must not be null");
        this.pdp = Objects.requireNonNull(pdp, "pdp must not be null");
        this.auditPublisher = (auditPublisher == null) ? SecurityAuditPublisher.noop() : auditPublisher;
        this.identitySupplier = () -> {
            if (identitySupplier != null) {
                SecurityIdentity identity = identitySupplier.get();
                if (identity != null) {
                    return identity;
                }
            }
            return dev.langchain4j.security.context.SecurityContextHolder.getIdentity().orElse(null);
        };
    }

    /**
     * Wraps a target tool instance in a security proxy interceptor.
     *
     * @param targetTool target tool object
     * @param pdp PolicyDecisionEngine instance
     * @param auditPublisher SecurityAuditPublisher instance
     * @param identitySupplier Supplier returning caller SecurityIdentity
     * @return proxied secure tool object
     */
    public static Object wrap(
        Object targetTool,
        PolicyDecisionEngine pdp,
        SecurityAuditPublisher auditPublisher,
        Supplier<SecurityIdentity> identitySupplier
    ) {
        Objects.requireNonNull(targetTool, "targetTool must not be null");
        Class<?> toolClass = targetTool.getClass();
        Class<?>[] interfaces = toolClass.getInterfaces();

        HardAbortToolExecutionInterceptor interceptor = new HardAbortToolExecutionInterceptor(
            targetTool, pdp, auditPublisher, identitySupplier
        );

        if (interfaces.length > 0) {
            return Proxy.newProxyInstance(
                toolClass.getClassLoader(),
                interfaces,
                interceptor
            );
        }

        try {
            Class<?> proxyClass = new net.bytebuddy.ByteBuddy()
                .subclass(toolClass)
                .method(net.bytebuddy.matcher.ElementMatchers.any())
                .intercept(net.bytebuddy.implementation.InvocationHandlerAdapter.of(interceptor))
                .make()
                .load(toolClass.getClassLoader(), net.bytebuddy.dynamic.loading.ClassLoadingStrategy.Default.INJECTION)
                .getLoaded();

            for (java.lang.reflect.Constructor<?> ctor : proxyClass.getDeclaredConstructors()) {
                try {
                    ctor.setAccessible(true);
                    Object[] dummyArgs = new Object[ctor.getParameterCount()];
                    return ctor.newInstance(dummyArgs);
                } catch (Exception ignored) {
                }
            }
        } catch (Throwable ignored) {
        }

        return targetTool;
    }

    /**
     * Pre-execution hook verifying security annotations and PDP evaluation before invoking tool.
     *
     * @param method tool method to execute
     * @param args invocation arguments array
     * @param identity caller security identity
     */
    public void beforeToolExecution(Method method, Object[] args, SecurityIdentity identity) {
        SecuredTool securedTool = resolveSecuredToolAnnotation(method);
        if (securedTool == null) {
            return; // Unannotated tools pass through
        }

        String toolName = targetTool.getClass().getSimpleName() + "#" + method.getName();
        Map<String, Object> argMap = buildArgumentMap(method, args);

        if (identity == null) {
            publishAudit(null, toolName, PolicyDecision.DENY, "UNAUTHENTICATED_TOOL_CALL", argMap);
            throw new ToolExecutionDeniedException(
                "Tool execution aborted: Unauthenticated caller attempted to invoke @" + toolName,
                null,
                toolName,
                "UNAUTHENTICATED_CALLER",
                argMap
            );
        }

        PolicyEvaluationRequest request = PolicyEvaluationRequest.builder()
            .subject(identity)
            .action(securedTool.action())
            .resource(toolName)
            .context(Map.of(
                "requiredRoles", Set.of(securedTool.requiredRoles()),
                "minClearance", securedTool.minClearance(),
                "requiredTenant", securedTool.requiredTenant(),
                "isMutative", securedTool.isMutative(),
                "arguments", argMap
            ))
            .build();

        PolicyDecision decision = pdp.evaluate(request);

        if (decision != PolicyDecision.PERMIT) {
            publishAudit(identity, toolName, decision, "TOOL_POLICY_VIOLATION", argMap);
            throw new ToolExecutionDeniedException(
                String.format("Hard abort: Caller '%s' denied execution of tool '%s'. Decision: %s",
                    identity.subjectId(), toolName, decision),
                identity,
                toolName,
                "TOOL_EXECUTION_DENIED",
                argMap
            );
        }

        publishAudit(identity, toolName, PolicyDecision.PERMIT, "TOOL_EXECUTE_PERMITTED", argMap);
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        if (method.getDeclaringClass() == Object.class) {
            return method.invoke(targetTool, args);
        }

        SecurityIdentity identity = identitySupplier.get();
        beforeToolExecution(method, args, identity);

        try {
            method.setAccessible(true);
            return method.invoke(targetTool, args);
        } catch (InvocationTargetException e) {
            throw e.getCause();
        }
    }

    private SecuredTool resolveSecuredToolAnnotation(Method method) {
        SecuredTool securedTool = method.getAnnotation(SecuredTool.class);
        if (securedTool != null) {
            return securedTool;
        }
        try {
            Method targetMethod = targetTool.getClass().getMethod(method.getName(), method.getParameterTypes());
            return targetMethod.getAnnotation(SecuredTool.class);
        } catch (NoSuchMethodException ignored) {
            return null;
        }
    }

    private Map<String, Object> buildArgumentMap(Method method, Object[] args) {
        Map<String, Object> map = new LinkedHashMap<>();
        if (args == null) {
            return map;
        }
        Parameter[] params = method.getParameters();
        for (int i = 0; i < args.length; i++) {
            String name = (i < params.length) ? params[i].getName() : "arg" + i;
            map.put(name, args[i]);
            map.put("arg" + i, args[i]);
        }
        return map;
    }

    private void publishAudit(SecurityIdentity id, String toolName, PolicyDecision decision, String reason, Map<String, Object> args) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
            .subjectId(id == null ? "UNAUTHENTICATED" : id.subjectId())
            .tenantId(id == null ? "UNKNOWN" : id.tenantId())
            .subjectRoles(id == null ? Set.of() : id.roles())
            .subjectClearance(id == null ? 0 : id.clearanceFloor())
            .enforcementPoint("TOOL_INTERCEPTOR")
            .action("tool:execute")
            .targetResource(toolName)
            .decision(decision == PolicyDecision.PERMIT ? "ALLOW" : "ABORT")
            .reasonCode(reason)
            .payloadSnapshot(args)
            .severity(decision == PolicyDecision.PERMIT ? "INFORMATIONAL" : "SECURITY_ALERT")
            .build();
        auditPublisher.publish(event);
    }
}
