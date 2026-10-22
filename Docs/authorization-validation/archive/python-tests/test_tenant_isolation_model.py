#!/usr/bin/env python3
"""Offline tests locking the tenant-isolation bounded model's verdicts.

These tests pin the cross-tenant contamination properties checked by
``tenant_isolation_model.py``: full-scoping safety, the chain-structure
necessity lattice, the per-gate defense-in-depth table, and accounting
conservation. A rename or semantic change on either side must fail here
and force an explicit sync. Run:

    python -m unittest discover -s Docs/authorization-validation/tools \
        -t Docs/authorization-validation/tools \
        -p "test_tenant_isolation_model.py" -v
"""

import unittest

import tenant_isolation_model as tim


class TenantIsolationHypothesesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = tim.check_tenant_hypotheses()

    def test_overall_status_pass(self):
        self.assertEqual(self.report["status"], "PASS")

    def test_every_hypothesis_passes(self):
        for entry in self.report["hypotheses"]:
            self.assertEqual(
                entry["status"], "PASS",
                "%s failed: %s" % (entry["id"], entry["statement"]),
            )

    def test_t1_full_scoping_is_contamination_free(self):
        evidence = self.report["hypotheses"][0]["evidence"]
        self.assertEqual(evidence["admittedForeignGrant"], 0)
        self.assertEqual(evidence["admittedContaminatedInputs"], 0)
        self.assertEqual(evidence["deniedCrossTenantBlock"], 0)
        # T1's own unpublished narrowing must still yield PENDING: per-tenant
        # admission safety composes with tenancy.
        self.assertGreater(evidence["deniedOwnPending"], 0)

    def test_t3_lattice_matches_chain_predicate(self):
        evidence = self.report["hypotheses"][1]["evidence"]
        self.assertEqual(evidence["subsetsChecked"], 30)
        self.assertEqual(evidence["contaminatingSubsets"], 20)
        self.assertEqual(evidence["unexpectedSafeSubsets"], [])
        # The single-gate probe vector is the only single-omission
        # contamination; every other single omission is covered.
        singles = [e for e in evidence["lattice"] if len(e["removed"]) == 1]
        self.assertEqual(len(singles), 5)
        for entry in singles:
            self.assertEqual(
                entry["contaminating"],
                entry["removed"] == ["tenant_scoped_probe"],
                entry["removed"],
            )

    def test_t5_configuration_count_matches_audited_lattice(self):
        evidence = self.report["hypotheses"][3]["evidence"]
        self.assertEqual(evidence["configurationsAudited"], 31)
        self.assertEqual(
            evidence["configurationsAudited"],
            1 + len(list(tim._subsets(tim.GATES))),
        )

    def test_t4_defense_in_depth_table_locked(self):
        observed = self.report["hypotheses"][2]["evidence"]["observed"]
        self.assertEqual(observed["tenant_scoped_cache_key"], [])
        self.assertEqual(observed["tenant_scoped_record_validation"], [])
        self.assertEqual(observed["tenant_scoped_watermark"], [])
        self.assertEqual(observed["tenant_scoped_match"], [])
        self.assertEqual(
            observed["tenant_scoped_probe"],
            ["admittedContaminatedInputs", "deniedCrossTenantBlock"],
        )


class TenantModelSemanticsTest(unittest.TestCase):
    """Direct enumeration checks on representative configurations."""

    def test_cache_vector_needs_both_gates_removed(self):
        # Removing only the cache key keeps record validation: the foreign
        # record is rejected fail-closed and the strict fallback is clean.
        prem = {gate: True for gate in tim.GATES}
        prem["tenant_scoped_cache_key"] = False
        buckets, _ = tim.enumerate_traces(prem)
        self.assertNotIn("admittedForeignGrant", buckets)
        # Removing record validation too opens the cache vector, but the
        # match gate still blocks the foreign grant (chain structure).
        prem["tenant_scoped_record_validation"] = False
        buckets, _ = tim.enumerate_traces(prem)
        self.assertNotIn("admittedForeignGrant", buckets)
        self.assertIn("deniedNoMatch", buckets)
        # Removing the match gate as well admits the foreign grant.
        prem["tenant_scoped_match"] = False
        buckets, _ = tim.enumerate_traces(prem)
        self.assertIn("admittedForeignGrant", buckets)

    def test_cross_tenant_block_requires_unscoped_probe(self):
        # T2's narrowing can never block T1's clean request while the
        # probe is tenant-scoped.
        prem = {gate: True for gate in tim.GATES}
        prem["tenant_scoped_probe"] = False
        for probe_read in ("T1", "T2"):
            pass  # the model enumerates both; the bucket appears only here
        buckets, details = tim.enumerate_traces(prem)
        self.assertIn("deniedCrossTenantBlock", buckets)
        for detail in details:
            if detail["bucket"] == "deniedCrossTenantBlock":
                self.assertEqual(detail["t1Narrowing"], "none")
                self.assertEqual(
                    detail["t2Narrowing"], "committed-unpublished"
                )
        prem_full = {gate: True for gate in tim.GATES}
        buckets_full, _ = tim.enumerate_traces(prem_full)
        self.assertNotIn("deniedCrossTenantBlock", buckets_full)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
