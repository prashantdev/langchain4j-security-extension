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
    String[] requiredRoles() default {};
    int minClearance() default 0;
    String requiredTenant() default "";
    boolean isMutative() default false;
    String action() default "tool:execute";
}
