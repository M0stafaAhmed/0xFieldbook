// Display outcomes confirmed by the examination participant, rather than
// conflating retained raw output with flag acquisition/submission.
import { EVIDENCE_PINS, STATE_EXPLANATION, STATE_LABEL, type EvidenceState } from "./evidence-pins";

export { EVIDENCE_PINS, STATE_EXPLANATION, STATE_LABEL, stateTone, type EvidenceState } from "./evidence-pins";

export interface EvidenceItem {
  machine: string;
  objective: "user" | "root";
  state: EvidenceState;
  label: string;
  explanation: string;
  quotes: string[];
}

/** Source-document existence remains validated separately by the vault/routes pipeline. */
export function buildEvidence(_bodies: Map<string, string>): EvidenceItem[] {
  return EVIDENCE_PINS.map((pin) => ({
    machine: pin.machine,
    objective: pin.objective,
    state: pin.state,
    label: STATE_LABEL[pin.state],
    explanation: STATE_EXPLANATION[pin.state],
    quotes: [],
  }));
}
