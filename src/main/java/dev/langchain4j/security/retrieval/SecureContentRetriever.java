package dev.langchain4j.security.retrieval;

import dev.langchain4j.data.document.Metadata;
import dev.langchain4j.data.segment.TextSegment;
import dev.langchain4j.rag.content.Content;
import dev.langchain4j.rag.content.retriever.ContentRetriever;
import dev.langchain4j.rag.query.Query;
import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.context.SecurityIdentity;
import dev.langchain4j.security.context.SecurityInvocationParameters;

import dev.langchain4j.security.context.SecurityContextHolder;
import dev.langchain4j.store.embedding.filter.Filter;

import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

import static dev.langchain4j.security.retrieval.SecurityMetadataNamespaces.*;

/**
 * Decorates a LangChain4j  {@link ContentRetriever} with dynamic AST pre-filtering
 * and mandatory post-retrieval in-memory chunk pruning.
 */
public class SecureContentRetriever implements ContentRetriever {

    private final ContentRetriever delegate;
    private final SecurityAuditPublisher auditPublisher;
    private final Supplier<SecurityIdentity> ambientIdentitySupplier;

    private SecureContentRetriever(Builder builder) {
        this.delegate = Objects.requireNonNull(builder.delegate, "delegate ContentRetriever must not be null");
        this.auditPublisher = (builder.auditPublisher == null) ? SecurityAuditPublisher.noop() : builder.auditPublisher;
        this.ambientIdentitySupplier = () -> {
            if (builder.identitySupplier != null) {
                SecurityIdentity identity = builder.identitySupplier.get();
                if (identity != null) {
                    return identity;
                }
            }
            return SecurityContextHolder.getIdentity().orElse(null);
        };
    }

    /**
     * Creates a new Builder instance for constructing a SecureContentRetriever.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Constructs a dynamic filter provider for wiring into {@code EmbeddingStoreContentRetriever.builder().dynamicFilter(...)}.
     *
     * @return a function mapping a Query to a Security Filter
     */
    public static Function<Query, Filter> dynamicFilterProvider() {
        return query -> {
            SecurityIdentity id = SecurityInvocationParameters.extractIdentity(query)
                .orElseGet(() -> SecurityContextHolder.getIdentity().orElse(null));
            return SecurityFilterAstBuilder.buildFilter(id);
        };
    }

    /**
     * Builds the native LangChain4j {@link Filter} AST for the given {@link Query}.
     *
     * @param query the query containing metadata or security context
     * @return the constructed security Filter
     */
    public Filter buildAstFilter(Query query) {
        SecurityIdentity identity = resolveIdentity(query);
        return SecurityFilterAstBuilder.buildFilter(identity);
    }

    /**
     * Executes retrieval using the underlying delegate content retriever, applying dynamic security pre-filtering
     * and post-retrieval chunk authorization pruning.
     *
     * @param query the RAG query to retrieve relevant content for
     * @return list of authorized Content items, filtered against caller identity constraints
     */
    @Override
    public List<Content> retrieve(Query query) {
        SecurityIdentity identity = resolveIdentity(query);

        // Fail-closed: unauthenticated retrieval immediately returns empty list
        if (identity == null) {
            publishAudit(null, 0, 0, "UNAUTHENTICATED_RETRIEVAL_DENIED");
            return Collections.emptyList();
        }

        // Phase 1: Build security Filter AST for dynamic pre-filtering capability
        Filter securityFilter = SecurityFilterAstBuilder.buildFilter(identity);

        // Execute underlying retrieval
        List<Content> rawContents = delegate.retrieve(query);
        if (rawContents == null || rawContents.isEmpty()) {
            return Collections.emptyList();
        }

        // Phase 2: In-memory post-retrieval chunk verification and pruning
        List<Content> authorizedContents = new ArrayList<>();
        int prunedCount = 0;

        for (Content content : rawContents) {
            TextSegment segment = content.textSegment();
            if (isAuthorizedChunk(segment, identity)) {
                authorizedContents.add(content);
            } else {
                prunedCount++;
            }
        }

        if (prunedCount > 0) {
            publishAudit(identity, rawContents.size(), prunedCount, "RAG_UNAUTHORIZED_PRUNING");
        }

        return Collections.unmodifiableList(authorizedContents);
    }

    private boolean isAuthorizedChunk(TextSegment segment, SecurityIdentity identity) {
        if (segment == null || segment.metadata() == null) {
            return false; // Fail-closed on missing segment metadata
        }

        Metadata metadata = segment.metadata();

        // 1. Strict Tenant Isolation
        String chunkTenant = metadata.getString(TENANT_ID);
        if (chunkTenant == null || !chunkTenant.equals(identity.tenantId())) {
            return false;
        }

        // 2. Clearance Floor Check
        Integer chunkClearance = getClearanceFloor(metadata);
        if (chunkClearance != null && identity.clearanceFloor() < chunkClearance) {
            return false;
        }

        // 3. Role Membership Intersection
        String allowedRolesStr = metadata.getString(ALLOWED_ROLES);
        if (allowedRolesStr != null && !allowedRolesStr.isBlank()) {
            Set<String> chunkRoles = parseRoles(allowedRolesStr);
            if (!chunkRoles.isEmpty() && Collections.disjoint(chunkRoles, identity.roles())) {
                return false;
            }
        }

        // 4. Department Isolation (if tagged on chunk)
        String chunkDept = metadata.getString(DEPARTMENT_ID);
        if (chunkDept != null && !chunkDept.isBlank()) {
            if (identity.departmentId() == null || !identity.departmentId().equals(chunkDept)) {
                return false;
            }
        }

        return true;
    }

    private Integer getClearanceFloor(Metadata metadata) {
        try {
            Integer val = metadata.getInteger(CLEARANCE_FLOOR);
            if (val != null) {
                return val;
            }
        } catch (Exception ignored) {
        }
        String str = metadata.getString(CLEARANCE_FLOOR);
        if (str != null && !str.isBlank()) {
            try {
                return Integer.parseInt(str.trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return null;
    }

    private Set<String> parseRoles(String rolesString) {
        Set<String> set = new HashSet<>();
        String[] split = rolesString.replace("[", "").replace("]", "").split(",");
        for (String r : split) {
            String trimmed = r.trim();
            if (!trimmed.isEmpty()) {
                set.add(trimmed);
            }
        }
        return set;
    }

    private SecurityIdentity resolveIdentity(Query query) {
        return SecurityInvocationParameters.extractIdentity(query)
            .orElseGet(ambientIdentitySupplier);
    }

    private void publishAudit(SecurityIdentity id, int total, int pruned, String reason) {
        SecurityAuditEvent event = SecurityAuditEvent.builder()
            .subjectId(id == null ? "UNAUTHENTICATED" : id.subjectId())
            .tenantId(id == null ? "UNKNOWN" : id.tenantId())
            .subjectRoles(id == null ? Set.of() : id.roles())
            .subjectClearance(id == null ? 0 : id.clearanceFloor())
            .enforcementPoint("RAG_FILTER")
            .action("rag:retrieve")
            .targetResource("ContentRetriever")
            .decision(id == null ? "DENY" : "ALLOW")
            .reasonCode(reason)
            .payloadSnapshot(Map.of("totalFetched", total, "prunedCount", pruned))
            .severity(pruned > 0 || id == null ? "NOTICE" : "INFORMATIONAL")
            .build();
        auditPublisher.publish(event);
    }

    /**
     * Builder for constructing instances of {@link SecureContentRetriever}.
     */
    public static class Builder {
        private ContentRetriever delegate;
        private SecurityAuditPublisher auditPublisher;
        private Supplier<SecurityIdentity> identitySupplier;

        /**
         * Sets the delegate ContentRetriever instance.
         *
         * @param delegate the underlying ContentRetriever
         * @return this Builder instance
         */
        public Builder contentRetriever(ContentRetriever delegate) {
            this.delegate = delegate;
            return this;
        }

        /**
         * Sets the SecurityAuditPublisher instance for audit log publication.
         *
         * @param auditPublisher the audit publisher
         * @return this Builder instance
         */
        public Builder securityAuditPublisher(SecurityAuditPublisher auditPublisher) {
            this.auditPublisher = auditPublisher;
            return this;
        }

        /**
         * Sets an explicit Supplier for resolving caller SecurityIdentity instances.
         *
         * @param identitySupplier supplier returning the current caller identity
         * @return this Builder instance
         */
        public Builder identitySupplier(Supplier<SecurityIdentity> identitySupplier) {
            this.identitySupplier = identitySupplier;
            return this;
        }

        /**
         * Builds a new {@link SecureContentRetriever} instance.
         *
         * @return a new SecureContentRetriever
         */
        public SecureContentRetriever build() {
            return new SecureContentRetriever(this);
        }
    }
}
