package com.coreryblack.astrlIdentity.experimental;

import com.coreryblack.astral_general.common.annotation.BusinessScanIgnore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Internal TDSC-only control endpoint. It has no production bean. */
@RestController
@Profile("tdsc-fault")
@ConditionalOnProperty(prefix = "app.identity.session-resilience.experimental-post-claim-gate",
        name = "enabled", havingValue = "true")
@BusinessScanIgnore
@RequestMapping("/_internal/tdsc/session-projection-gate")
public class TdscPostClaimGateController {

    private static final String NONCE_HEADER = "X-TDSC-Gate-Nonce";

    private final TdscPostClaimGate gate;

    public TdscPostClaimGateController(TdscPostClaimGate gate) {
        this.gate = gate;
    }

    @PostMapping("/arm")
    public ResponseEntity<TdscPostClaimGate.GateStatus> arm(
            @RequestHeader(value = NONCE_HEADER, required = false) String nonce) {
        if (!gate.arm(nonce)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(gate.status(nonce));
    }

    @PostMapping("/release")
    public ResponseEntity<TdscPostClaimGate.GateStatus> release(
            @RequestHeader(value = NONCE_HEADER, required = false) String nonce) {
        if (!gate.release(nonce)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
        return ResponseEntity.ok(gate.status(nonce));
    }

    @GetMapping
    public ResponseEntity<TdscPostClaimGate.GateStatus> status(
            @RequestHeader(value = NONCE_HEADER, required = false) String nonce) {
        TdscPostClaimGate.GateStatus status = gate.status(nonce);
        return status == null ? ResponseEntity.status(HttpStatus.FORBIDDEN).build() : ResponseEntity.ok(status);
    }
}
