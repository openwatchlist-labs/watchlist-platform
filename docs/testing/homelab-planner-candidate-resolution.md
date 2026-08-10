# H1 planner candidate-pack resolution

The H1 planner must resolve the candidate pack from the governed review state when that state pins an r1.12 `binding_candidates_v2_*` set. The pinned file must exist and match `candidate_pack_sha256`.

Historical `binding-candidates.v1.json` evidence is retained for audit, but it must never preempt a valid governed v2 pack because of path ordering or modification time. Strict v1 rejection remains active when no valid v2 pack exists.

The repair does not modify candidate, selection, review, acceptance, promotion, or evidence files.
