# langcharin4j-security-extension :
A zero-trust extension for LangChain4j, acting as a Policy Enforcement Point (PEP). Protect enterprise AI workflows with deterministic tool execution boundaries, dynamic multi-tenant RAG pre-filtering, deterministic tool interception, fail-stop hard aborts and OCSF audit logging.

## Enterprise Use Cases addressed by `langchain4j-security-extension`:

`langchain4j-security-extension` functions as a decoupled Policy Enforcement Point (PEP) for LangChain4j applications. 

---

### 1. Agent Access Control & Service Boundary Guarding
* **Preventing Unauthorized Agent Invocations:** Enforces role-based and clearance-based entry checks on AI Service interfaces using dynamic proxies (`SecureAiServices`), ensuring unauthorized callers cannot invoke specific agents (e.g., stopping non-admin users from invoking a `RemediationAgent`).
* **Fail-Closed Execution Gateways:** Intercepts invocations **before** any prompt transmission or token generation takes place, preventing token waste or unauthorized model interactions.

---

### 2. Tool Execution Protection & Function-Calling Authorization
* **Unauthorized Tool Interception:** Prevents LLMs from triggering sensitive Java tool functions (`@SecuredTool`) without verified caller entitlements.
* **Fine-Grained Parameter Constraints (ABAC via CEL):** Evaluates tool argument payloads against caller identity attributes at runtime using Common Expression Language (e.g., verifying `args.serverName` belongs to `subject.department`).
* **Dual-Mode Violation Handling:**
  * **Hard Abort (Mutative Tools):** Halts tool dispatch immediately via `ToolExecutionDeniedException` to block illegal state changes (e.g., preventing unauthorized database updates or server reboots).
  * **Model Feedback (Informational Tools):** Suppresses tool execution while returning prompt-safe refusal payloads (`ACCESS_DENIED`) back to the model context, allowing the LLM to explain operational limitations to the user.
* **Model Retry Budget & Brute-Force Prevention:** Tracks consecutive soft refusals per invocation to prevent models from exhausting tokens or scanning tool endpoints.

---

### 3. Multi-Tenant & Clearance-Aware RAG Retrieval
* **Cross-Tenant Vector Isolation:** Dynamically translates caller tenant boundaries (`sec:tenant_id`) into native LangChain4j vector database filter ASTs to prevent multi-tenant data leakage.
* **Clearance & Role Document Filtering:** Restricts vector retrieval to chunks matching caller clearance floors (`sec:clearance_floor`) and roles (`sec:allowed_roles`).
* **Post-Retrieval Chunk Pruning:** Acts as a safety net by inspecting metadata envelopes (`sec:*`) on returned `TextSegment`s and pruning unauthorized chunks if vector databases lack native AST filtering support.
* **Top-K Result Compensation (Oversampling & Secondary Paging):** Inflates candidate retrieval counts ($K_{fetch} = K_{target} \times 3.0$) and executes adaptive secondary fetches to prevent RAG context starvation caused by post-pruning.

---

### 4. Automated Secure Document Ingestion Pipeline
* **Standardized Metadata Tagging (`sec:*` Envelopes):** Attaches mandatory, tamper-evident security classification tags (`sec:tenant_id`, `sec:allowed_roles`, `sec:clearance_floor`, `sec:envelope_hash`) onto chunks during vector ingestion.
* **Structural & Header Document Parsing:** Automatically parses document structure (e.g., `## [CONFIDENTIAL]`) to elevate security clearance requirements for specific document sections.
* **DLP & Scanner Integration:** Provides SPI extension points (`ChunkSecurityEnricherSPI`) for integrating enterprise Data Loss Prevention (DLP) scanners or custom regex rules into the ingestion flow.
* **Fail-Closed Ingestion Checkpoints:** Enforces strict validation rules to reject unclassified or malformed documents before they are indexed into vector stores.

---

### 5. In-Band Security Context & Identity Propagation
* **Thread-Agnostic Propagation:** Packs `SecurityIdentity` into LangChain4j `InvocationParameters` so caller credentials seamlessly flow across thread pools, reactive pipelines, and multi-agent handoffs without context loss or thread-local leaks.
* **Enterprise Framework Integration:** Automatically resolves caller credentials from framework auth contexts (Spring Security `SecurityContextHolder`, Quarkus `SecurityIdentity`) via dedicated starters (`security-spring-starter`, `security-quarkus-starter`).

---

### 6. Decoupled Policy Governance & Engine Offloading
* **Embedded In-Memory Engine:** Evaluates role hierarchies (Role DAG) and clearance ranks (Clearance Lattice) within the local JVM using strict deny-overrides logic.
* **Centralized Enterprise PDP Delegation:** Offloads policy evaluation tuples `(Subject, Action, Resource, Context)` to external policy engines (such as Open Policy Agent / OPA or AWS Cedar) via `RemotePDPAdapter`.
* **Two-Tier Decision Caching:** Deduplicates identical policy checks across agent loops and cross-request invocations to minimize policy evaluation overhead.

---

### 7. Security Observability, Threat Telemetry & SIEM Exporting
* **Asynchronous Non-Blocking Auditing:** Publishes OCSF/ECS-aligned audit logs without introducing latency into LLM inference loops.
* **AI Threat Vector Detection:** Logs specialized threat events such as:
  * **Prompt Injection & Instruction Overrides**
  * **Tenant Boundary Violations & Identity Spoofing**
  * **Role Elevation / Privilege Escalation**
  * **Policy Brute-Force Scanning**
* **In-Flight Data Sanitization:** Automatically redacts API keys, secrets, private keys, Bearer tokens, and `@Masked` parameter fields from audit records.
* **Enterprise SIEM Exporters:** Streams security events directly to enterprise monitoring solutions via Splunk HEC, Elastic Common Schema (ECS), and OpenTelemetry LogRecord exporters.
