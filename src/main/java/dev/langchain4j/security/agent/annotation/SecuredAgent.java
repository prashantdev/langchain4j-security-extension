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
    String[] requiredRoles() default {};
    int minClearance() default 0;
    String requiredTenant() default "";
    String description() default "";
}
