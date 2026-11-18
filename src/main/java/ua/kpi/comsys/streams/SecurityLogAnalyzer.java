package ua.kpi.comsys.streams;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Gatherer;
import java.util.stream.Stream;

public class SecurityLogAnalyzer {
    public Optional<SecurityLog> findFirstCriticalEvent(Stream<SecurityLog> stream) {
        checkStream(stream);
        return stream.filter(log -> "CRITICAL".equals(log.severityLevel())).findFirst();
    }

    // The input is ordered by timestamp. The event at the deadline is excluded.
    public List<SecurityLog> getLogsBeforeDeadline(Stream<SecurityLog> stream,
                                                  LocalDateTime deadline) {
        checkStream(stream);
        if (deadline == null) {
            throw new IllegalArgumentException("deadline cannot be null");
        }
        return stream.takeWhile(log -> log.timestamp().isBefore(deadline)).toList();
    }

    public List<String> detectIpBursts(Stream<SecurityLog> stream,
                                       int burstThreshold, int maxIpsToReport) {
        checkStream(stream);
        if (burstThreshold <= 0) {
            throw new IllegalArgumentException("burstThreshold must be greater than 0");
        }
        if (maxIpsToReport <= 0) {
            throw new IllegalArgumentException("maxIpsToReport must be greater than 0");
        }
        return stream.sequential().gather(ipBursts(burstThreshold))
                .limit(maxIpsToReport).toList();
    }

    private static Gatherer<SecurityLog, BurstState, String> ipBursts(int threshold) {
        return Gatherer.ofSequential(BurstState::new, (state, log, downstream) -> {
            String ip = log.ipAddress();
            if (state.count == 0 || !java.util.Objects.equals(state.ip, ip)) {
                state.ip = ip;
                state.count = 1;
            } else if (state.count < threshold) {
                state.count++;
            } else {
                return true; // This consecutive run was already reported.
            }
            if (state.count == threshold) {
                return downstream.push(ip);
            }
            return true;
        });
    }

    private static class BurstState {
        String ip;
        int count;
    }

    private static void checkStream(Stream<SecurityLog> stream) {
        if (stream == null) {
            throw new IllegalArgumentException("stream cannot be null");
        }
    }
}
