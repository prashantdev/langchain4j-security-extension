package dev.langchain4j.security.context;

import java.util.Map;
import java.util.Optional;

/**
 * Service Provider Interface (SPI) for resolving {@link SecurityIdentity} from invocation contexts.
 */
@FunctionalInterface
public interface IdentityBridge {

    /**
     * Resolves the caller's {@link SecurityIdentity} from invocation parameters.
     *
     * @param parameters the invocation parameters carrier, may be null
     * @return an {@link Optional} containing the resolved identity, or empty if unresolved
     */
    Optional<SecurityIdentity> resolveIdentity(InvocationParameters parameters);

    /**
     * Resolves the caller's {@link SecurityIdentity} from a context map.
     *
     * @param contextMap the context attributes map, may be null
     * @return an {@link Optional} containing the resolved identity, or empty if unresolved
     */
    default Optional<SecurityIdentity> resolveIdentity(Map<String, Object> contextMap) {
        return resolveIdentity(InvocationParameters.from(contextMap));
    }
}
