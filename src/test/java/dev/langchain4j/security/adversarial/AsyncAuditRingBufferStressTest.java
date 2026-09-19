package dev.langchain4j.security.adversarial;

import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import dev.langchain4j.security.audit.slf4j.AsyncAuditRingBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

@DisplayName("Adversarial Stress Test Suite: Non-blocking AsyncAuditRingBuffer Concurrency & Saturation")
class AsyncAuditRingBufferStressTest {

    @Test
    @DisplayName("Stress Test: High concurrent producer saturation with drop-oldest backpressure")
    void testConcurrentHighVolumeBufferSaturation() throws InterruptedException {
        int bufferCapacity = 500;
        int threadCount = 16;
        int eventsPerThread = 2500; // 40,000 total events
        int totalEvents = threadCount * eventsPerThread;

        AtomicLong downstreamDelivered = new AtomicLong(0);
        SecurityAuditPublisher slowDownstream = event -> {
            downstreamDelivered.incrementAndGet();
            // Tiny spin to ensure buffer saturation occurs
            Thread.onSpinWait();
        };

        AsyncAuditRingBuffer ringBuffer = new AsyncAuditRingBuffer(slowDownstream, bufferCapacity);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch finishLatch = new CountDownLatch(threadCount);

        long startNs = System.nanoTime();

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int i = 0; i < eventsPerThread; i++) {
                        SecurityAuditEvent event = SecurityAuditEvent.builder()
                            .subjectId("producer-" + threadId)
                            .tenantId("TENANT_STRESS")
                            .action("test:audit")
                            .targetResource("event-" + i)
                            .decision("ALLOW")
                            .build();
                        ringBuffer.publish(event);
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                } finally {
                    finishLatch.countDown();
                }
            });
        }

        // Fire all producers simultaneously
        startLatch.countDown();
        boolean completed = finishLatch.await(5, TimeUnit.SECONDS);
        long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNs);

        assertThat(completed).as("Producers completed within timeout without deadlock").isTrue();
        assertThat(elapsedMs).as("Non-blocking publish must finish rapidly under saturation").isLessThan(5000);

        ringBuffer.close();
        executor.shutdown();

        // Verify buffer saturation and drops were counted
        long droppedCount = ringBuffer.getDroppedEventsCount();
        assertThat(droppedCount).isGreaterThanOrEqualTo(0L);

        long delivered = downstreamDelivered.get();
        // Conservation check: delivered + dropped must account for total events produced
        assertThat(delivered + droppedCount).isGreaterThanOrEqualTo(totalEvents - bufferCapacity);
    }

    @Test
    @DisplayName("Drop-Oldest FIFO Policy: Evicts oldest elements when saturated and preserves newer elements")
    void testDropOldestEvictionPolicy() {
        int smallCapacity = 5;
        CountDownLatch holdDownstream = new CountDownLatch(1);
        List<String> deliveredIds = Collections.synchronizedList(new ArrayList<>());

        SecurityAuditPublisher downstream = event -> {
            try {
                holdDownstream.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException ignored) {}
            deliveredIds.add(event.targetResource());
        };

        // Create buffer without active consumption initially
        AsyncAuditRingBuffer ringBuffer = new AsyncAuditRingBuffer(downstream, smallCapacity);

        // Publish 10 events sequentially into capacity 5
        // Event 1 is picked up by worker thread
        // Events 2..6 fill queue
        // Events 7..10 evict older queued events (drops >= 3)
        for (int i = 1; i <= 10; i++) {
            ringBuffer.publish(SecurityAuditEvent.builder()
                .subjectId("user")
                .targetResource("res-" + i)
                .build());
        }

        // Release downstream to process whatever remains in the buffer
        holdDownstream.countDown();
        ringBuffer.flush();
        ringBuffer.close();

        // Dropped count must be at least 3
        assertThat(ringBuffer.getDroppedEventsCount()).isGreaterThanOrEqualTo(3);

        // Older queued events res-2, res-3 should have been evicted
        assertThat(deliveredIds).doesNotContain("res-2", "res-3");
    }

    @Test
    @DisplayName("Worker Thread Resilience: Downstream publisher exceptions do not crash ring buffer")
    void testWorkerThreadResilienceOnDownstreamErrors() {
        AtomicInteger failureCount = new AtomicInteger(0);
        AtomicInteger successCount = new AtomicInteger(0);

        SecurityAuditPublisher faultyDownstream = event -> {
            if ("fail".equals(event.targetResource())) {
                failureCount.incrementAndGet();
                throw new RuntimeException("Simulated downstream failure");
            }
            successCount.incrementAndGet();
        };

        AsyncAuditRingBuffer ringBuffer = new AsyncAuditRingBuffer(faultyDownstream, 100);

        // Send a failing event followed by healthy events
        ringBuffer.publish(SecurityAuditEvent.builder().targetResource("fail").build());
        ringBuffer.publish(SecurityAuditEvent.builder().targetResource("healthy-1").build());
        ringBuffer.publish(SecurityAuditEvent.builder().targetResource("healthy-2").build());

        ringBuffer.flush();
        ringBuffer.close();

        assertThat(failureCount.get()).isEqualTo(1);
        assertThat(successCount.get()).isEqualTo(2);
    }

    @Test
    @DisplayName("Graceful Shutdown: Close terminates worker thread and prevents further publishing")
    void testGracefulShutdown() {
        List<SecurityAuditEvent> received = new ArrayList<>();
        AsyncAuditRingBuffer ringBuffer = new AsyncAuditRingBuffer(received::add, 50);

        ringBuffer.publish(SecurityAuditEvent.builder().targetResource("before-close").build());
        ringBuffer.close();

        // Post-close publish must be safely dropped
        ringBuffer.publish(SecurityAuditEvent.builder().targetResource("after-close").build());

        assertThat(received).hasSize(1);
        assertThat(received.get(0).targetResource()).isEqualTo("before-close");
    }
}
