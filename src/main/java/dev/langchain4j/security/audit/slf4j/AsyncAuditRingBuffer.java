package dev.langchain4j.security.audit.slf4j;

import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * High-throughput non-blocking asynchronous ring buffer preventing audit logging
 * from adding latency to inference.
 */
public class AsyncAuditRingBuffer implements SecurityAuditPublisher {

    private static final Logger log = LoggerFactory.getLogger(AsyncAuditRingBuffer.class);
    private static final int DEFAULT_CAPACITY = 16384;

    private final BlockingQueue<SecurityAuditEvent> queue;
    private final SecurityAuditPublisher downstreamPublisher;
    private final Thread workerThread;
    private final AtomicLong droppedEvents = new AtomicLong(0);
    private volatile boolean running = true;

    /**
     * Constructs an AsyncAuditRingBuffer with the default capacity.
     *
     * @param downstreamPublisher downstream audit publisher to dispatch events to
     */
    public AsyncAuditRingBuffer(SecurityAuditPublisher downstreamPublisher) {
        this(downstreamPublisher, DEFAULT_CAPACITY);
    }

    /**
     * Constructs an AsyncAuditRingBuffer with a specified buffer capacity.
     *
     * @param downstreamPublisher downstream audit publisher to dispatch events to
     * @param capacity maximum number of audit events allowed in the buffer
     */
    public AsyncAuditRingBuffer(SecurityAuditPublisher downstreamPublisher, int capacity) {
        this.downstreamPublisher = Objects.requireNonNull(downstreamPublisher, "downstreamPublisher must not be null");
        int cap = capacity <= 0 ? DEFAULT_CAPACITY : capacity;
        this.queue = new ArrayBlockingQueue<>(cap);
        this.workerThread = new Thread(this::drainLoop, "langchain4j-security-audit-worker");
        this.workerThread.setDaemon(true);
        this.workerThread.start();
    }

    @Override
    public void publish(SecurityAuditEvent event) {
        if (!running || event == null) {
            return;
        }

        // Non-blocking offer: if full, drop oldest and retry offer
        if (!queue.offer(event)) {
            queue.poll(); // Evict oldest
            if (!queue.offer(event)) {
                // In case another thread filled it
                queue.poll();
                queue.offer(event);
            }
            long drops = droppedEvents.incrementAndGet();
            if (drops % 1000 == 1) {
                log.warn("[AsyncAuditRingBuffer] Buffer saturated. Total dropped events: {}", drops);
            }
        }
    }

    private void drainLoop() {
        while (running || !queue.isEmpty()) {
            try {
                SecurityAuditEvent event = queue.poll(50, TimeUnit.MILLISECONDS);
                if (event != null) {
                    downstreamPublisher.publish(event);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("[AsyncAuditRingBuffer] Failed to dispatch audit event: {}", e.getMessage(), e);
            }
        }
    }

    /**
     * Returns the total count of dropped audit events due to buffer saturation.
     *
     * @return total count of dropped audit events
     */
    public long getDroppedEventsCount() {
        return droppedEvents.get();
    }

    @Override
    public void flush() {
        // Wait briefly for queue to drain if events are pending
        long deadline = System.currentTimeMillis() + 1000;
        while (!queue.isEmpty() && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        downstreamPublisher.flush();
    }

    @Override
    public void close() {
        running = false;
        try {
            workerThread.join(2000);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
        downstreamPublisher.flush();
        downstreamPublisher.close();
    }
}
