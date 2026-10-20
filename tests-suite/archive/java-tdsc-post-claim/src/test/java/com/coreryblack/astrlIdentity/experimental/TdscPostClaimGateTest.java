package com.coreryblack.astrlIdentity.experimental;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class TdscPostClaimGateTest {

    @Test
    void armedGateAcknowledgesClaimThenReleasesWorker() throws Exception {
        TdscPostClaimGate gate = new TdscPostClaimGate("test-nonce", 5_000L);

        assertThat(gate.arm("test-nonce")).isTrue();
        CompletableFuture<Boolean> waitingWorker = CompletableFuture.supplyAsync(gate::awaitAfterClaim);
        awaitState(gate, "test-nonce", "CLAIMED_WAITING");

        assertThat(gate.release("test-nonce")).isTrue();
        assertThat(waitingWorker.get(2, TimeUnit.SECONDS)).isTrue();
        assertThat(gate.status("test-nonce").state()).isEqualTo("RELEASED");
    }

    @Test
    void rejectsInvalidNonceWithoutDisclosingGateState() {
        TdscPostClaimGate gate = new TdscPostClaimGate("test-nonce", 5_000L);

        assertThat(gate.arm("wrong-nonce")).isFalse();
        assertThat(gate.status("wrong-nonce")).isNull();
        assertThat(gate.release("wrong-nonce")).isFalse();
    }

    @Test
    void boundedWaitExpiresWhenNoReleaseArrives() {
        TdscPostClaimGate gate = new TdscPostClaimGate("test-nonce", 1L);

        assertThat(gate.arm("test-nonce")).isTrue();
        assertThat(gate.awaitAfterClaim()).isTrue();
        assertThat(gate.status("test-nonce").state()).isEqualTo("TIMED_OUT");
    }

    @Test
    void completedGateCannotBeRearmed() throws Exception {
        TdscPostClaimGate gate = new TdscPostClaimGate("test-nonce", 5_000L);
        assertThat(gate.arm("test-nonce")).isTrue();
        CompletableFuture<Boolean> waitingWorker = CompletableFuture.supplyAsync(gate::awaitAfterClaim);
        awaitState(gate, "test-nonce", "CLAIMED_WAITING");

        assertThat(gate.release("test-nonce")).isTrue();
        assertThat(waitingWorker.get(2, TimeUnit.SECONDS)).isTrue();
        assertThat(gate.arm("test-nonce")).isFalse();
    }

    @Test
    void recordsLeaseLossOnlyForReleasedGatedClaim() throws Exception {
        TdscPostClaimGate gate = new TdscPostClaimGate("test-nonce", 5_000L);
        assertThat(gate.arm("test-nonce")).isTrue();
        CompletableFuture<Boolean> waitingWorker = CompletableFuture.supplyAsync(gate::awaitAfterClaim);
        awaitState(gate, "test-nonce", "CLAIMED_WAITING");

        assertThat(gate.release("test-nonce")).isTrue();
        assertThat(waitingWorker.get(2, TimeUnit.SECONDS)).isTrue();
        gate.acknowledgeLeaseLost();

        TdscPostClaimGate.GateStatus status = gate.status("test-nonce");
        assertThat(status.state()).isEqualTo("LEASE_LOST");
        assertThat(status.leaseLostAcknowledgements()).isEqualTo(1L);
    }

    private void awaitState(TdscPostClaimGate gate, String nonce, String expected) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (System.nanoTime() < deadline) {
            TdscPostClaimGate.GateStatus status = gate.status(nonce);
            if (status != null && expected.equals(status.state())) {
                return;
            }
            Thread.sleep(5L);
        }
        assertThat(gate.status(nonce).state()).isEqualTo(expected);
    }
}
