import { act, render } from '@testing-library/react'
import { Router, type Navigator } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'

import {
  installHistoryLeaveGuard,
  useHistoryLeaveGuard,
  withoutHistoryLeaveGuard,
} from '../utils/historyLeaveGuard'

function makeNavigator() {
  const push = vi.fn()
  const replace = vi.fn()
  const go = vi.fn()
  const navigator = {
    createHref: vi.fn(() => '/'),
    push,
    replace,
    go,
  } as unknown as Navigator
  return { navigator, push, replace, go }
}

function GuardHarness({ active, guard }: { active: boolean; guard: () => Promise<boolean> }) {
  useHistoryLeaveGuard(guard, active)
  return null
}

function renderGuard(navigator: Navigator, guard: () => Promise<boolean>, active = true) {
  return render(
    <Router location="/" navigator={navigator}>
      <GuardHarness active={active} guard={guard} />
    </Router>,
  )
}

async function settleGuard() {
  await act(async () => {
    await Promise.resolve()
  })
}

describe('history leave guard', () => {
  it('guards router navigation, supports a confirmed bypass, and restores the navigator', async () => {
    window.history.replaceState({ idx: 4 }, '', '/')
    const { navigator, push, replace, go } = makeNavigator()
    const guard = vi.fn()
      .mockResolvedValueOnce(false)
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(true)
    const view = renderGuard(navigator, guard)

    navigator.push('/blocked', undefined)
    await settleGuard()
    expect(push).not.toHaveBeenCalled()

    navigator.replace('/accepted', undefined)
    await settleGuard()
    expect(replace).toHaveBeenCalledWith('/accepted', undefined)

    navigator.go(-1)
    await settleGuard()
    expect(go).toHaveBeenCalledWith(-1)

    withoutHistoryLeaveGuard(() => navigator.push('/confirmed', undefined))
    expect(push).toHaveBeenCalledWith('/confirmed', undefined)
    expect(() => withoutHistoryLeaveGuard(() => { throw new Error('stop') })).toThrow('stop')

    view.unmount()
    navigator.push('/after-unmount', undefined)
    expect(push).toHaveBeenCalledWith('/after-unmount', undefined)
  })

  it('does not navigate when a pending confirmation outlives its registration', async () => {
    let resolveGuard: ((accepted: boolean) => void) | undefined
    const guard = vi.fn(() => new Promise<boolean>(resolve => { resolveGuard = resolve }))
    const { navigator, push } = makeNavigator()
    const view = renderGuard(navigator, guard)

    navigator.push('/later', undefined)
    view.unmount()
    resolveGuard?.(true)
    await settleGuard()

    expect(push).not.toHaveBeenCalled()
  })

  it('restores a browser pop before confirmation and replays it only when accepted', async () => {
    const addEventListener = vi.spyOn(window, 'addEventListener')
    const historyGo = vi.spyOn(window.history, 'go').mockImplementation(() => undefined)
    installHistoryLeaveGuard()
    installHistoryLeaveGuard()
    const listener = addEventListener.mock.calls.find(([type]) => type === 'popstate')?.[1]
    expect(listener).toBeTypeOf('function')
    const handlePopState = listener as EventListener

    handlePopState(new PopStateEvent('popstate', { state: { idx: 1 } }))
    expect(historyGo).not.toHaveBeenCalled()

    window.history.replaceState({ idx: 5 }, '', '/')
    const { navigator } = makeNavigator()
    const guard = vi.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false)
    const view = renderGuard(navigator, guard)

    handlePopState(new PopStateEvent('popstate', { state: null }))
    handlePopState(new PopStateEvent('popstate', { state: { idx: 5 } }))
    expect(historyGo).not.toHaveBeenCalled()

    const firstPop = new PopStateEvent('popstate', { state: { idx: 3 } })
    const stopFirst = vi.spyOn(firstPop, 'stopImmediatePropagation')
    handlePopState(firstPop)
    expect(stopFirst).toHaveBeenCalled()
    expect(historyGo).toHaveBeenLastCalledWith(2)

    const firstRestore = new PopStateEvent('popstate', { state: { idx: 5 } })
    const stopRestore = vi.spyOn(firstRestore, 'stopImmediatePropagation')
    handlePopState(firstRestore)
    await settleGuard()
    expect(stopRestore).toHaveBeenCalled()
    expect(historyGo).toHaveBeenLastCalledWith(-2)

    handlePopState(new PopStateEvent('popstate', { state: { idx: 3 } }))
    expect(historyGo).toHaveBeenCalledTimes(2)

    handlePopState(new PopStateEvent('popstate', { state: { idx: 4 } }))
    handlePopState(new PopStateEvent('popstate', { state: { idx: 5 } }))
    await settleGuard()
    expect(historyGo).toHaveBeenCalledTimes(3)

    view.unmount()
    historyGo.mockClear()
    window.history.replaceState({}, '', '/')
    const noIndex = renderGuard(makeNavigator().navigator, vi.fn().mockResolvedValue(true))
    handlePopState(new PopStateEvent('popstate', { state: { idx: 2 } }))
    expect(historyGo).not.toHaveBeenCalled()
    noIndex.unmount()
  })
})
