package com.coreryblack.astrlIdentity.experimental;

import com.coreryblack.astrlIdentity.service.SessionProjectionPostClaimGate;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * One-shot, bounded control point for the isolated TDSC lease experiment.
 * The class is not instantiated unless both the test profile and property are enabled.
 */
@Component
@Profile("tdsc-fault")
@ConditionalOnProperty(prefix = "app.identity.session-resilience.experimental-post-claim-gate",
        name = "enabled", havingValue = "true")
public class TdscPostClaimGate implements SessionProjectionPostClaimGate {

    private final ReentrantLock lock = new ReentrantLock();
    private final Condition changed = lock.newCondition();
    private final String configuredNonce;
    private final long waitTimeoutMillis;

    private GateState state = GateState.IDLE;
    private long armSequence;
    private long acknowledgedClaims;
    private long leaseLostAcknowledgements;

    public TdscPostClaimGate(
            @Value("${app.identity.session-resilience.experimental-post-claim-gate.nonce:}") String configuredNonce,
            @Value("${app.identity.session-resilience.experimental-post-claim-gate.wait-timeout-ms:15000}")
            long waitTimeoutMillis) {
        this.configuredNonce = configuredNonce;
        this.waitTimeoutMillis = Math.max(1L, Math.min(waitTimeoutMillis, 120_000L));
    }

    public boolean arm(String nonce) {
        if (!nonceMatches(nonce)) {
            return false;
        }
        lock.lock();
        try {
            if (state != GateState.IDLE) {
                return false;
            }
            armSequence++;
            state = GateState.ARMED;
            changed.signalAll();
            return true;
        } finally {
            lock.unlock();
        }
    }

    public boolean release(String nonce) {
        if (!nonceMatches(nonce)) {
            return false;
        }
        lock.lock();
        try {
            if (state != GateState.CLAIMED_WAITING) {
                return false;
            }
            state = GateState.RELEASED;
            changed.signalAll();
            return true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public boolean awaitAfterClaim() {
        lock.lock();
        try {
            if (state != GateState.ARMED) {
                return false;
            }
            state = GateState.CLAIMED_WAITING;
            acknowledgedClaims++;
            changed.signalAll();
            long remainingNanos = TimeUnit.MILLISECONDS.toNanos(waitTimeoutMillis);
            while (state == GateState.CLAIMED_WAITING && remainingNanos > 0L) {
                try {
                    remainingNanos = changed.awaitNanos(remainingNanos);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                    state = GateState.INTERRUPTED;
                    changed.signalAll();
                    return true;
                }
            }
            if (state == GateState.CLAIMED_WAITING) {
                state = GateState.TIMED_OUT;
                changed.signalAll();
            }
            return true;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void acknowledgeLeaseLost() {
        lock.lock();
        try {
            if (state == GateState.RELEASED) {
                leaseLostAcknowledgements++;
                state = GateState.LEASE_LOST;
                changed.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    public GateStatus status(String nonce) {
        if (!nonceMatches(nonce)) {
            return null;
        }
        lock.lock();
        try {
            return new GateStatus(state.name(), armSequence, acknowledgedClaims, leaseLostAcknowledgements);
        } finally {
            lock.unlock();
        }
    }

    private boolean nonceMatches(String nonce) {
        if (!StringUtils.hasText(configuredNonce) || !StringUtils.hasText(nonce)) {
            return false;
        }
        return MessageDigest.isEqual(configuredNonce.getBytes(StandardCharsets.UTF_8),
                nonce.getBytes(StandardCharsets.UTF_8));
    }

    public record GateStatus(String state, long armSequence, long acknowledgedClaims,
                             long leaseLostAcknowledgements) {
    }

    private enum GateState {
        IDLE,
        ARMED,
        CLAIMED_WAITING,
        RELEASED,
        LEASE_LOST,
        TIMED_OUT,
        INTERRUPTED
    }
}
