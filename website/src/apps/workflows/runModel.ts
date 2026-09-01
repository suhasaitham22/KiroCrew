/**
 * Pure event-stream → view-model helpers shared by the Workflows page, the
 * chat WorkflowProgressBar (expanded tree), and the ActivityViewer Workflows
 * sidebar. Extracted from WorkflowsPage so all three surfaces fold the same
 * `workflow_run_event` stream into the same phase tree + budget snapshot.
 *
 * Pure / non-mutating. Unit-tested in src/test/WorkflowsPage.test.ts via the
 * re-exports in WorkflowsPage.tsx.
 */

export interface WfEvent {
  run_id: string
  seq: number
  ts: string
  type: string
  /** Unvalidated wire payload: the backend sends a different set of fields per
   *  `type`, and nothing here parses it, so every read is coerced at the point
   *  the `type` check has already picked the shape. */
  data: Record<string, unknown>
}

/** One payload field as the string the view model needs, or `undefined` when the
 *  event omits it (or carries something else there). */
function asString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined
}

/** One payload field as a number, with the same "absent or wrong type is absent"
 *  rule as `asString`. */
function asNumber(v: unknown): number | undefined {
  return typeof v === 'number' ? v : undefined
}

export interface AgentRow {
  agent_id: string
  label?: string
  last_tool?: string
  ok?: boolean
}

export interface PhaseGroup {
  title: string
  agents: AgentRow[]
}

/** Fold a run event stream into ordered phases each holding their agent rows. */
export function groupByPhase(events: WfEvent[]): PhaseGroup[] {
  const phases: PhaseGroup[] = []
  const byId = new Map<string, AgentRow>()
  let current = ''
  const ensure = (title: string): PhaseGroup => {
    let p = phases.find(x => x.title === title)
    if (!p) { p = { title, agents: [] }; phases.push(p) }
    return p
  }
  for (const e of events) {
    if (e.type === 'phase_started') {
      current = asString(e.data.title) || ''
      ensure(current)
    } else if (e.type === 'agent_started') {
      // One binding for the id so the row and its map key cannot disagree when
      // the event omits `agent_id` — both fold under the empty id.
      const agentId = asString(e.data.agent_id) ?? ''
      const row: AgentRow = { agent_id: agentId, label: asString(e.data.label) }
      byId.set(agentId, row)
      ensure(asString(e.data.phase) ?? current).agents.push(row)
    } else if (e.type === 'agent_progress') {
      const row = byId.get(asString(e.data.agent_id) ?? '')
      if (row) row.last_tool = asString(e.data.last_tool)
    } else if (e.type === 'agent_finished') {
      const row = byId.get(asString(e.data.agent_id) ?? '')
      if (row) row.ok = !!e.data.ok
    }
  }
  return phases
}

/**
 * Whether a run's originating `session_key` belongs to a given chat slot.
 *
 * A chat-launched run is tagged with the session_key the gateway resolves for the
 * slot, which is the slot's history key: ``dashboard:<slotKey>`` (see
 * ``_history_key_for`` on the backend). So a run belongs to slot ``chat-1-123``
 * when its session_key is ``dashboard:chat-1-123`` (or, defensively, ends with the
 * slot key). A run with NO session_key (UI-launched, no chat link) belongs to no
 * chat slot and is shown only in the standalone Workflows tab — never pinned to a
 * chat. This is what keeps an active run in ITS chat, not every open chat.
 */
export function runBelongsToSlot(sessionKey: string | undefined | null, slotKey: string | undefined | null): boolean {
  if (!sessionKey || !slotKey) return false
  if (sessionKey === slotKey) return true
  if (sessionKey === `dashboard:${slotKey}`) return true
  // Tolerate a leading "dashboard:" / "dashboard_" prefix on either side.
  return normalizeRunSessionKey(sessionKey) === normalizeRunSessionKey(slotKey)
}

/** Canonical form of a run's `session_key` — and of a slot key — for
 *  cross-referencing the two without pairwise `runBelongsToSlot` scans: a map
 *  of runs keyed by `normalizeRunSessionKey(session_key)` is looked up with
 *  `normalizeRunSessionKey(slotKey)` and matches exactly the pairs
 *  `runBelongsToSlot` accepts. Strips one leading "dashboard:" (the history
 *  key the gateway tags chat-launched runs with) or "dashboard_" (persisted
 *  key form) prefix. */
export function normalizeRunSessionKey(s: string): string {
  return s.replace(/^dashboard[:_]/, '')
}

/** Latest budget snapshot from the stream, if any. */
export function latestBudget(events: WfEvent[]): { spent: number; total: number | null } | null {
  let out: { spent: number; total: number | null } | null = null
  for (const e of events) {
    if (e.type === 'run_started') out = { spent: 0, total: asNumber(e.data.budget_total) ?? null }
    else if (e.type === 'budget_update') {
      const prevTotal: number | null = out ? out.total : null
      // An update with no `spent` reports nothing spent rather than NaN.
      out = { spent: asNumber(e.data.spent) ?? 0, total: prevTotal }
    }
  }
  return out
}
