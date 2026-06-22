import unittest

from netapp_asup_alertcheck.models import (
    AnalysisResult,
    Classification,
    EmailMessageInput,
    EvidenceBundle,
    OutputEnvelope,
)


class ModelTests(unittest.TestCase):
    def test_models_are_mutable_dataclasses(self):
        classification = Classification(
            matched_rule_id="arw_activity_seen",
            alert_type="ransomware",
            parser="arw",
            confidence=0.96,
            matched_signals=["subject_contains"],
        )

        classification.confidence = 0.5

        self.assertEqual(classification.confidence, 0.5)

    def test_analysis_result_omits_ai_error_when_none(self):
        analysis = AnalysisResult(
            status="possible_ransomware_activity_detected",
            severity="high",
            confidence=0.86,
            impacted_objects=[],
            recommended_actions=[],
            ai_error=None,
        )

        self.assertNotIn("ai_error", analysis.to_dict())

    def test_analysis_result_includes_ai_error_when_provided(self):
        analysis = AnalysisResult(
            status="possible_ransomware_activity_detected",
            severity="high",
            confidence=0.86,
            impacted_objects=[],
            recommended_actions=[],
            ai_error={"code": "invalid_json", "details": {"line": 1}},
        )

        data = analysis.to_dict()

        self.assertEqual(data["ai_error"], {"code": "invalid_json", "details": {"line": 1}})

    def test_evidence_bundle_serializes_with_defensive_nested_copy(self):
        evidence = EvidenceBundle(
            summary=[{"volume": {"name": "Netapp_A20_LUN00"}}],
            files_used=[{"path": "arw-vol-status.xml"}],
            raw_refs=[{"line": {"number": 12}}],
        )

        data = evidence.to_dict()
        data["summary"][0]["volume"]["name"] = "mutated"

        self.assertEqual(evidence.summary[0]["volume"]["name"], "Netapp_A20_LUN00")

    def test_output_envelope_serializes_kb_with_defensive_nested_copy(self):
        envelope = OutputEnvelope(
            message=EmailMessageInput(
                received_at="2026-06-21T18:05:28+08:00",
                from_address="Kmuh_a20@kmuh.gov.tw",
                subject="[external] POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                headers={},
                attachments=[],
            ),
            classification=Classification(
                matched_rule_id="arw_activity_seen",
                alert_type="ransomware",
                parser="arw",
                confidence=0.96,
                matched_signals=[],
            ),
            evidence=EvidenceBundle(summary=[], files_used=[], raw_refs=[]),
            analysis=AnalysisResult(
                status="possible_ransomware_activity_detected",
                severity="high",
                confidence=0.86,
                impacted_objects=[],
                recommended_actions=[],
                ai_error=None,
            ),
            kb={"results": [{"title": "KB"}]},
            warnings=[],
            errors=[],
        )

        data = envelope.to_dict()
        data["kb"]["results"][0]["title"] = "mutated"

        self.assertEqual(envelope.kb["results"][0]["title"], "KB")

    def test_output_envelope_serializes_to_expected_shape(self):
        envelope = OutputEnvelope(
            message=EmailMessageInput(
                received_at="2026-06-21T18:05:28+08:00",
                from_address="Kmuh_a20@kmuh.gov.tw",
                subject="[external] POSSIBLE RANSOMWARE ACTIVITY DETECTED",
                headers={"X-Netapp-asup-hostname": "KMUH-Netapp-AFF-A20-01"},
                attachments=["body.7z"],
            ),
            classification=Classification(
                matched_rule_id="arw_activity_seen",
                alert_type="ransomware",
                parser="arw",
                confidence=0.96,
                matched_signals=["subject_contains", "header_trigger"],
            ),
            evidence=EvidenceBundle(summary=[], files_used=[], raw_refs=[]),
            analysis=AnalysisResult(
                status="possible_ransomware_activity_detected",
                severity="high",
                confidence=0.86,
                impacted_objects=[],
                recommended_actions=[],
                ai_error=None,
            ),
            kb={"search_required": False, "queries": [], "results": []},
            warnings=[],
            errors=[],
        )

        data = envelope.to_dict()

        self.assertEqual(data["message"]["from"], "Kmuh_a20@kmuh.gov.tw")
        self.assertEqual(data["classification"]["matched_rule_id"], "arw_activity_seen")
        self.assertEqual(data["analysis"]["severity"], "high")
        self.assertEqual(data["errors"], [])


if __name__ == "__main__":
    unittest.main()
