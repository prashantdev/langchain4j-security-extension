package dev.langchain4j.security.retrieval;

/**
 * Standard metadata namespace constants for chunk security classification.
 */
public final class SecurityMetadataNamespaces {

    /** Metadata key for schema version. */
    public static final String SCHEMA_VERSION = "sec:schema_version";

    /** Metadata key for tenant ID. */
    public static final String TENANT_ID = "sec:tenant_id";

    /** Metadata key for clearance floor rank. */
    public static final String CLEARANCE_FLOOR = "sec:clearance_floor";

    /** Metadata key for allowed roles list. */
    public static final String ALLOWED_ROLES = "sec:allowed_roles";

    /** Metadata key for department ID. */
    public static final String DEPARTMENT_ID = "sec:department_id";

    /** Metadata key for document ID. */
    public static final String DOCUMENT_ID = "sec:document_id";

    /** Metadata key for chunk index. */
    public static final String CHUNK_INDEX = "sec:chunk_index";

    /** Metadata key for classification level name. */
    public static final String CLASSIFICATION_LEVEL = "sec:classification_level";

    /** Sentinel metadata key value used to enforce deny-all for unauthenticated queries. */
    public static final String DENY_ALL_SENTINEL = "__DENY_ALL_UNAUTHENTICATED__";

    private SecurityMetadataNamespaces() {}
}
