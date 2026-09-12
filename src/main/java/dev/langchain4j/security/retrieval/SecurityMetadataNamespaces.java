package dev.langchain4j.security.retrieval;

/**
 * Standard metadata namespace constants for chunk security classification.
 */
public final class SecurityMetadataNamespaces {

    public static final String SCHEMA_VERSION = "sec:schema_version";
    public static final String TENANT_ID = "sec:tenant_id";
    public static final String CLEARANCE_FLOOR = "sec:clearance_floor";
    public static final String ALLOWED_ROLES = "sec:allowed_roles";
    public static final String DEPARTMENT_ID = "sec:department_id";
    public static final String DOCUMENT_ID = "sec:document_id";
    public static final String CHUNK_INDEX = "sec:chunk_index";
    public static final String CLASSIFICATION_LEVEL = "sec:classification_level";

    public static final String DENY_ALL_SENTINEL = "__DENY_ALL_UNAUTHENTICATED__";

    private SecurityMetadataNamespaces() {}
}
