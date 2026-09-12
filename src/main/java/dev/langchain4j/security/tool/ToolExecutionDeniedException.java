package dev.langchain4j.security.tool;

import dev.langchain4j.security.context.SecurityIdentity;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Thrown upon unauthorized tool execution to immediately halt the agentic loop.
 */
public class ToolExecutionDeniedException extends RuntimeException {

    private final SecurityIdentity subject;
    private final String toolName;
    private final String reasonCode;
    private final Map<String, Object> arguments;

    public ToolExecutionDeniedException(
        String message,
        SecurityIdentity subject,
        String toolName,
        String reasonCode,
        Map<String, Object> arguments
    ) {
        super(message);
        this.subject = subject;
        this.toolName = toolName;
        this.reasonCode = reasonCode;
        if (arguments == null || arguments.isEmpty()) {
            this.arguments = Map.of();
        } else {
            this.arguments = Collections.unmodifiableMap(new HashMap<>(arguments));
        }
    }

    public SecurityIdentity getSubject() {
        return subject;
    }

    public String getToolName() {
        return toolName;
    }

    public String getReasonCode() {
        return reasonCode;
    }

    public Map<String, Object> getArguments() {
        return arguments;
    }
}
