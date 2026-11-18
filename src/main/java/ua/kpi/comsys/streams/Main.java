package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

public class Main {
    public static void main(String[] args) {
        var analyzer = new SecurityLogAnalyzer();
        var start = LocalDateTime.of(2026, 11, 18, 10, 0);
        var reads = new AtomicInteger();
        var event = analyzer.findFirstCriticalEvent(Stream.iterate(0, i -> i + 1)
                .map(i -> new SecurityLog("192.168.1.10", i == 3 ? "CRITICAL" : "INFO",
                        "Event " + i, start.plusSeconds(i)))
                .peek(log -> reads.incrementAndGet()));
        System.out.println("First critical: " + event.map(SecurityLog::eventDescription)
                .orElse("not found"));
        System.out.println("Events read: " + reads.get());

        var before = analyzer.getLogsBeforeDeadline(Stream.iterate(0, i -> i + 1)
                .map(i -> new SecurityLog("192.168.1.10", "INFO", "Event " + i,
                        start.plusSeconds(i))), start.plusSeconds(3));
        System.out.println("Before deadline: " + before.size());
        var burstReads = new AtomicInteger();
        var bursts = analyzer.detectIpBursts(Stream.iterate(0, i -> i + 1)
                .map(i -> new SecurityLog("10.0.0." + (i / 3 + 1), "WARNING",
                        "Failed login", start.plusSeconds(i)))
                .peek(log -> burstReads.incrementAndGet()), 3, 2);
        System.out.println("IP bursts: " + bursts);
        System.out.println("Burst events read: " + burstReads.get());
        System.out.println("Empty stream: " + analyzer.findFirstCriticalEvent(Stream.empty())
                .map(SecurityLog::eventDescription).orElse("not found"));
    }
}
