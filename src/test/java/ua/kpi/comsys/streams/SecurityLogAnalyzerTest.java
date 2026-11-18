package ua.kpi.comsys.streams;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(2)
class SecurityLogAnalyzerTest {
    private final SecurityLogAnalyzer analyzer = new SecurityLogAnalyzer();
    private final LocalDateTime start = LocalDateTime.of(2026, 11, 18, 10, 0);
    private SecurityLog log(String ip, String level, int seconds) {
        return new SecurityLog(ip, level, "event " + seconds, start.plusSeconds(seconds));
    }
    private Stream<SecurityLog> ips(String... addresses) {
        return Stream.of(addresses).map(ip -> log(ip, "INFO", 0));
    }
    @Test void findsFirstCritical() {
        var first = log("a", "CRITICAL", 1);
        assertEquals(first, analyzer.findFirstCriticalEvent(Stream.of(
                log("a", "INFO", 0), first, log("b", "CRITICAL", 2))).orElseThrow());
    }
    @Test void emptyCriticalSearch() {
        assertTrue(analyzer.findFirstCriticalEvent(Stream.empty()).isEmpty());
    }
    @Test void noCriticalMatch() {
        assertTrue(analyzer.findFirstCriticalEvent(Stream.of(log("a", "WARNING", 0))).isEmpty());
    }
    @Test void severityIsCaseSensitive() {
        assertTrue(analyzer.findFirstCriticalEvent(Stream.of(log("a", "critical", 0))).isEmpty());
    }
    @Test void infiniteCriticalSearchStopsExactly() {
        var read = new AtomicInteger();
        var result = analyzer.findFirstCriticalEvent(Stream.iterate(0, i -> i + 1)
                .map(i -> log("a", i == 4 ? "CRITICAL" : "INFO", i))
                .peek(x -> read.incrementAndGet()));
        assertEquals("CRITICAL", result.orElseThrow().severityLevel());
        assertEquals(5, read.get());
    }
    @Test void deadlineExcludesEqualTimestamp() {
        assertEquals(2, analyzer.getLogsBeforeDeadline(Stream.of(
                log("a", "INFO", 0), log("a", "INFO", 1), log("a", "INFO", 2)),
                start.plusSeconds(2)).size());
    }
    @Test void deadlineStopsAtFirstBoundary() {
        assertTrue(analyzer.getLogsBeforeDeadline(Stream.of(
                log("a", "INFO", 2), log("a", "INFO", 0)), start.plusSeconds(1)).isEmpty());
    }
    @Test void emptyDeadlineResult() {
        assertTrue(analyzer.getLogsBeforeDeadline(Stream.empty(), start).isEmpty());
    }
    @Test void finiteStreamBeforeDeadline() {
        assertEquals(2, analyzer.getLogsBeforeDeadline(Stream.of(log("a", "INFO", 0),
                log("a", "INFO", 1)), start.plusSeconds(10)).size());
    }
    @Test void infiniteDeadlineStopsExactly() {
        var read = new AtomicInteger();
        var result = analyzer.getLogsBeforeDeadline(Stream.iterate(0, i -> i + 1)
                .map(i -> log("a", "INFO", i)).peek(x -> read.incrementAndGet()), start.plusSeconds(3));
        assertEquals(3, result.size());
        assertEquals(4, read.get()); // takeWhile must inspect the boundary element.
    }
    @Test void detectsBurstAtThreshold() {
        assertEquals(List.of("a"), analyzer.detectIpBursts(ips("a", "a", "a"), 3, 10));
    }
    @Test void interruptedRunsDoNotCombine() {
        assertTrue(analyzer.detectIpBursts(ips("a", "a", "b", "a", "a"), 3, 10).isEmpty());
    }
    @Test void longRunReportedOnce() {
        assertEquals(List.of("a"), analyzer.detectIpBursts(ips("a", "a", "a", "a", "a"), 2, 10));
    }
    @Test void sameIpCanFormNewBurst() {
        assertEquals(List.of("a", "b", "a"), analyzer.detectIpBursts(
                ips("a", "a", "b", "b", "a", "a"), 2, 10));
    }
    @Test void thresholdOneReportsEachRun() {
        assertEquals(List.of("a", "b"), analyzer.detectIpBursts(ips("a", "a", "b"), 1, 10));
    }
    @Test void emptyBurstResult() {
        assertTrue(analyzer.detectIpBursts(Stream.empty(), 2, 3).isEmpty());
    }
    @Test void incompleteFinalRunIsNotReported() {
        assertTrue(analyzer.detectIpBursts(ips("a", "a"), 3, 10).isEmpty());
    }
    @Test void reportLimitStopsExactlyOnInfiniteStream() {
        var read = new AtomicInteger();
        var result = analyzer.detectIpBursts(Stream.iterate(0, i -> i + 1)
                .map(i -> log("ip" + i / 3, "INFO", i))
                .peek(x -> read.incrementAndGet()), 3, 2);
        assertEquals(List.of("ip0", "ip1"), result);
        assertEquals(6, read.get());
    }
    @Test void constantInfiniteStreamStopsAfterFirstBurst() {
        var read = new AtomicInteger();
        assertEquals(List.of("a"), analyzer.detectIpBursts(Stream.generate(
                () -> { read.incrementAndGet(); return log("a", "INFO", 0); }), 4, 1));
        assertEquals(4, read.get());
    }
    @Test void parallelInputPreservesRunOrder() {
        assertEquals(List.of("a", "b"), analyzer.detectIpBursts(
                ips("a", "a", "b", "b").parallel(), 2, 10));
    }
    @Test void nullStreamsRejected() {
        assertThrows(IllegalArgumentException.class, () -> analyzer.findFirstCriticalEvent(null));
        assertThrows(IllegalArgumentException.class, () -> analyzer.getLogsBeforeDeadline(null, start));
        assertThrows(IllegalArgumentException.class, () -> analyzer.detectIpBursts(null, 2, 3));
    }
    @Test void nullDeadlineRejected() {
        assertThrows(IllegalArgumentException.class,
                () -> analyzer.getLogsBeforeDeadline(Stream.empty(), null));
    }
    @ParameterizedTest @ValueSource(ints = {0, -1, Integer.MIN_VALUE})
    void invalidThreshold(int threshold) {
        assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(Stream.empty(), threshold, 1));
    }
    @ParameterizedTest @ValueSource(ints = {0, -1, Integer.MIN_VALUE})
    void invalidReportLimit(int limit) {
        assertThrows(IllegalArgumentException.class,
                () -> analyzer.detectIpBursts(Stream.empty(), 1, limit));
    }
}
