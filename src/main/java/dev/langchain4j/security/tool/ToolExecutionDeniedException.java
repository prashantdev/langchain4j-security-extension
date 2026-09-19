package dev.langchain4j.security.tool;

import dev.langchain4j.security.context.SecurityIdentity;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Thrown upon unauthorized tool execution to immediately halt the agentic loop.
 */
public class ToolExecutionDeniedException extends RuntimeException {

    /** Security identity of the subject who attempted invocation. */
    private final SecurityIdentity subject;

    /** Name of the tool attempted. */
    private final String toolName;

    /** Security denial reason code. */
    private final String reasonCode;

    /** Snapshot map of tool invocation arguments. */
    private final Map<String, Object> arguments;

    /**
     * Constructs a new ToolExecutionDeniedException.
     *
     * @param message detailed denial message
     * @param subject security identity of caller
     * @param toolName name of denied tool
     * @param reasonCode denial reason code
     * @param arguments tool invocation arguments snapshot
     */
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

    /**
     * Returns the security identity of the caller who attempted execution.
     *
     * @return caller SecurityIdentity
     */
    public SecurityIdentity getSubject() {
        return subject;
    }

    /**
     * Returns the name of the denied tool.
     *
     * @return tool name string
     */
    public String getToolName() {
        return toolName;
    }

    /**
     * Returns the denial reason code.
     *
     * @return reason code string
     */
    public String getReasonCode() {
        return reasonCode;
    }

    /**
     * Returns an unmodifiable map of tool invocation arguments.
     *
     * @return arguments map
     */
    public Map<String, Object> getArguments() {
        return arguments;
    }
}
