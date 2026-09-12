package dev.langchain4j.security.agent;

import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.IdentityBridge;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.pdp.PolicyDecisionEngine;
import dev.langchain4j.security.tool.HardAbortToolExecutionInterceptor;
import dev.langchain4j.service.AiServices;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Decorator builder wrapping LangChain4j 1.19.0 {@link AiServices} to generate secured dynamic proxies.
 */
public class SecureAiServices<T> {

    private final Class<T> aiServiceClass;
    private final AiServices<T> underlyingBuilder;
    private PolicyDecisionEngine pdp;
    private SecurityAuditPublisher auditPublisher;
    private SecurityIdentity securityIdentity;
    private IdentityBridge identityBridge;
    private final List<Object> securedTools = new ArrayList<>();

    private SecureAiServices(Class<T> aiServiceClass) {
        this.aiServiceClass = Objects.requireNonNull(aiServiceClass, "aiServiceClass must not be null");
        this.underlyingBuilder = AiServices.builder(aiServiceClass);
    }

    public static <T> SecureAiServices<T> builder(Class<T> aiServiceClass) {
        return new SecureAiServices<>(aiServiceClass);
    }

    public SecureAiServices<T> policyDecisionEngine(PolicyDecisionEngine pdp) {
        this.pdp = pdp;
        return this;
    }

    public SecureAiServices<T> securityAuditPublisher(SecurityAuditPublisher auditPublisher) {
        this.auditPublisher = auditPublisher;
        return this;
    }

    public SecureAiServices<T> securityIdentity(SecurityIdentity securityIdentity) {
        this.securityIdentity = securityIdentity;
        return this;
    }

    public SecureAiServices<T> identityBridge(IdentityBridge identityBridge) {
        this.identityBridge = identityBridge;
        return this;
    }

    public SecureAiServices<T> chatModel(ChatModel chatModel) {
        underlyingBuilder.chatModel(chatModel);
        return this;
    }

    public SecureAiServices<T> chatLanguageModel(ChatModel chatModel) {
        return chatModel(chatModel);
    }

    public SecureAiServices<T> contentRetriever(ContentRetriever contentRetriever) {
        underlyingBuilder.contentRetriever(contentRetriever);
        return this;
    }

    public SecureAiServices<T> tools(Object... tools) {
        if (tools != null) {
            Collections.addAll(this.securedTools, tools);
        }
        return this;
    }

    public SecureAiServices<T> tools(List<Object> tools) {
        if (tools != null) {
            this.securedTools.addAll(tools);
        }
        return this;
    }

    @SuppressWarnings("unchecked")
    public T build() {
        Objects.requireNonNull(pdp, "PolicyDecisionEngine must be configured in SecureAiServices");

        // Wrap registered tools with HardAbortToolExecutionInterceptor PEP
        if (!securedTools.isEmpty()) {
            List<Object> wrappedTools = new ArrayList<>();
            for (Object tool : securedTools) {
                wrappedTools.add(HardAbortToolExecutionInterceptor.wrap(
                    tool, pdp, auditPublisher, () -> this.securityIdentity
                ));
            }
            underlyingBuilder.tools(wrappedTools);
        }

        T service = underlyingBuilder.build();

        AgentSecurityInvocationHandler handler = new AgentSecurityInvocationHandler(
            service,
            aiServiceClass,
            pdp,
            auditPublisher,
            securityIdentity
        );

        return (T) Proxy.newProxyInstance(
            aiServiceClass.getClassLoader(),
            new Class<?>[]{aiServiceClass},
            handler
        );
    }
}
