// Public completion presentation, based on the examination participant's explicit
// 2026-11-19 confirmation that the user and root flags were obtained and
// submitted on each of the five examination machines.
// This is an owner-attested outcome, not a claim that all raw responses survived
// in the historical archive. The earlier evidence audit remains in Git history.
export type EvidenceState = "Confirmed";

export const STATE_LABEL: Record<EvidenceState, string> = {
  Confirmed: "Obtained and submitted",
};

export const STATE_EXPLANATION: Record<EvidenceState, string> = {
  Confirmed: "Completion confirmed by the examination participant.",
};

export const stateTone = (_s: EvidenceState): string => "confirmed";

export interface EvidencePin {
  machine: string;
  objective: "user" | "root";
  state: EvidenceState;
}

const MACHINES = ["VE-01", "EA-01", "ME-01", "HA-01", "IN-01"] as const;
export const EVIDENCE_PINS: EvidencePin[] = MACHINES.flatMap(
  (machine): EvidencePin[] => [
    { machine, objective: "user", state: "Confirmed" },
    { machine, objective: "root", state: "Confirmed" },
  ],
);
