package dev.langchain4j.security.agent.annotation;

import java.lang.annotation.*;

/**
 * Declares security constraints on an AI Service interface or method.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
@Inherited
@Documented
public @interface SecuredAgent {
    /**
     * Set of required roles for invoking this agent or method.
     *
     * @return array of required roles
     */
    String[] requiredRoles() default {};

    /**
     * Minimum security clearance level required.
     *
     * @return minimum clearance rank
     */
    int minClearance() default 0;

    /**
     * Required tenant ID for multi-tenant isolation.
     *
     * @return required tenant ID, or empty string if open to any tenant
     */
    String requiredTenant() default "";

    /**
     * Description of the secured agent constraint.
     *
     * @return constraint description
     */
    String description() default "";
}
