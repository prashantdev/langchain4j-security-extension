package dev.langchain4j.security.audit.slf4j;

import dev.langchain4j.security.audit.SecurityAuditEvent;
import dev.langchain4j.security.audit.SecurityAuditPublisher;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class AsyncAuditRingBufferTest {

    @Test
    @DisplayName("Should publish 10,000 events in tight loop without blocking and drain successfully")
    void testHighThroughputPublishing() {
        List<SecurityAuditEvent> received = Collections.synchronizedList(new ArrayList<>());
        SecurityAuditPublisher downstream = received::add;

        try (AsyncAuditRingBuffer ringBuffer = new AsyncAuditRingBuffer(downstream, 20000)) {
            long start = System.currentTimeMillis();
            for (int i = 0; i < 10000; i++) {
                ringBuffer.publish(SecurityAuditEvent.builder()
                    .subjectId("user_" + i)
                    .action("test:action")
                    .build());
            }
            long elapsed = System.currentTimeMillis() - start;
            // 10,000 non-blocking offers should complete in < 2000 ms
            assertThat(elapsed).isLessThan(2000);

            ringBuffer.flush();
        }

        assertThat(received.size()).isEqualTo(10000);
    }

    @Test
    @DisplayName("Should drop oldest events when saturated and track droppedEventsCount")
    void testQueueSaturationAndDropOldest() {
        AtomicInteger processed = new AtomicInteger(0);
        // Downstream that pauses to force queue saturation
        SecurityAuditPublisher slowDownstream = event -> {
            try {
                Thread.sleep(10);
            } catch (InterruptedException ignored) {}
            processed.incrementAndGet();
        };

        // Small capacity buffer of 5 elements
        try (AsyncAuditRingBuffer ringBuffer = new AsyncAuditRingBuffer(slowDownstream, 5)) {
            for (int i = 0; i < 50; i++) {
                ringBuffer.publish(SecurityAuditEvent.builder()
                    .subjectId("user_" + i)
                    .build());
            }

            // At least some events should have been dropped due to saturation
            assertThat(ringBuffer.getDroppedEventsCount()).isGreaterThan(0);
        }
    }

    @Test
    @DisplayName("Should handle null event safely")
    void testNullEvent() {
        List<SecurityAuditEvent> received = new ArrayList<>();
        try (AsyncAuditRingBuffer ringBuffer = new AsyncAuditRingBuffer(received::add, 10)) {
            ringBuffer.publish(null);
            ringBuffer.flush();
        }
        assertThat(received).isEmpty();
    }
}
