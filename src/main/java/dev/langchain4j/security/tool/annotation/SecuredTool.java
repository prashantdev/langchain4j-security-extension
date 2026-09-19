package dev.langchain4j.security.tool.annotation;

import java.lang.annotation.*;

/**
 * Declares security requirements and execution mode on tool methods.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
@Inherited
@Documented
public @interface SecuredTool {
    /**
     * Required roles to execute this tool.
     *
     * @return array of required role names
     */
    String[] requiredRoles() default {};

    /**
     * Minimum security clearance level required to execute this tool.
     *
     * @return minimum clearance rank
     */
    int minClearance() default 0;

    /**
     * Required tenant ID for multi-tenant isolation.
     *
     * @return tenant ID string, or empty string if open to any tenant
     */
    String requiredTenant() default "";

    /**
     * Indicates whether executing this tool modifies persistent state.
     *
     * @return true if mutative, false otherwise
     */
    boolean isMutative() default false;

    /**
     * Security action identifier for PDP evaluation.
     *
     * @return action string
     */
    String action() default "tool:execute";
}
