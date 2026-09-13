export const POLICY_VERSION = 'demo-policy-v1';
const result = (verdict, css, reason, rule) => ({verdict, css, reason, rule});
export function evaluate(confidence, risk, verified) {
  if (!Number.isFinite(confidence) || confidence < 0 || confidence > 100 ||
      !['low', 'medium', 'high', 'critical'].includes(risk) || typeof verified !== 'boolean') {
    throw new TypeError('Invalid policy inputs');
  }
  if (risk === 'critical' && confidence < 90) return result('REJECT', 'rejectv', 'Critical risk requires at least 90% declared confidence.', 'critical_below_90');
  if (risk === 'high' && !verified) return result('REJECT', 'rejectv', 'High risk with unverified evidence.', 'high_unverified');
  if (confidence < 50) return result('SILENCE', 'silencev', 'Declared confidence is below the 50% floor.', 'confidence_below_50');
  if (!verified) return result('SILENCE', 'silencev', 'Evidence has not been declared complete and verified.', 'evidence_unverified');
  if (confidence < 80 || ['high', 'critical'].includes(risk)) return result('WAIT', 'waitv', 'Human review is required.', 'review_required');
  return result('ACT NOW', 'actv', 'Illustrative policy conditions met; no action was executed.', 'declared_evidence_threshold_met');
}
