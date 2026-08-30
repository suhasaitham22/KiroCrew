import { useContext, useLayoutEffect } from 'react'
import { UNSAFE_NavigationContext, type Navigator } from 'react-router-dom'

type LeaveGuard = () => Promise<boolean>

interface GuardRegistration {
  guard: LeaveGuard
  index: number | null
  navigator: Navigator
  push: Navigator['push']
  replace: Navigator['replace']
  go: Navigator['go']
}

let registration: GuardRegistration | null = null
let installed = false
let restoring = false
let replaying = false
let requestedDelta = 0
let bypassDepth = 0

function historyIndex(state: unknown): number | null {
  if (!state || typeof state !== 'object' || !('idx' in state)) return null
  const index = (state as { idx?: unknown }).idx
  return typeof index === 'number' ? index : null
}

function handlePopState(event: PopStateEvent) {
  if (replaying) {
    replaying = false
    return
  }

  const active = registration
  if (!active) return
  const nextIndex = historyIndex(event.state)
  if (nextIndex === null) return

  if (restoring) {
    event.stopImmediatePropagation()
    restoring = false
    void active.guard().then(accepted => {
      if (!accepted || registration !== active) return
      replaying = true
      window.history.go(requestedDelta)
    })
    return
  }

  if (active.index === null || nextIndex === active.index) return
  event.stopImmediatePropagation()
  requestedDelta = nextIndex - active.index
  restoring = true
  window.history.go(-requestedDelta)
}

/** Install before BrowserRouter so guarded POP events never reach its history listener. */
export function installHistoryLeaveGuard() {
  if (installed) return
  installed = true
  window.addEventListener('popstate', handlePopState)
}

function guardedNavigation(active: GuardRegistration, navigate: () => void, pop = false) {
  if (bypassDepth > 0 || registration !== active) {
    navigate()
    return
  }
  void active.guard().then(accepted => {
    if (!accepted || registration !== active) return
    if (pop) replaying = true
    navigate()
  })
}

/** Register the one active dirty editor at the router boundary. */
function registerHistoryLeaveGuard(guard: LeaveGuard, navigator: Navigator): () => void {
  const index = historyIndex(window.history.state)
  const push = navigator.push.bind(navigator)
  const replace = navigator.replace.bind(navigator)
  const go = navigator.go.bind(navigator)
  const active: GuardRegistration = { guard, index, navigator, push, replace, go }
  navigator.push = (...args) => guardedNavigation(active, () => push(...args))
  navigator.replace = (...args) => guardedNavigation(active, () => replace(...args))
  navigator.go = delta => guardedNavigation(active, () => go(delta), true)
  registration = active
  return () => {
    if (registration !== active) return
    registration = null
    navigator.push = push
    navigator.replace = replace
    navigator.go = go
  }
}

/** Guard every router push, replace, and programmatic back while an editor is dirty. */
export function useHistoryLeaveGuard(guard: LeaveGuard, active: boolean) {
  const { navigator } = useContext(UNSAFE_NavigationContext)
  useLayoutEffect(() => {
    if (!active) return
    return registerHistoryLeaveGuard(guard, navigator)
  }, [active, guard, navigator])
}

/** Perform a navigation whose user confirmation already succeeded. */
export function withoutHistoryLeaveGuard<T>(navigate: () => T): T {
  bypassDepth += 1
  try {
    return navigate()
  } finally {
    bypassDepth -= 1
  }
}
