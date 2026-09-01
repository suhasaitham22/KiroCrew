/**
 * The coarse-pointer scrollbar thumb must clear WCAG 1.4.11 (non-text contrast,
 * 3:1) against the elevated backdrop it scrolls over — in EVERY theme.
 *
 * On a coarse pointer the persistent thumb is the SOLE scroll affordance: there
 * is no hover state to fall back on, so a thumb below 3:1 leaves a user unable
 * to perceive that the box scrolls or where they are in it. The token is derived
 * from the stylesheet's own coarse-pointer branch rather than hardcoded, so a
 * future token swap is measured here instead of silently reintroducing the
 * failure.
 *
 * Machinery is shared, not re-derived: the WCAG math comes from
 * `lib/iconContrast` and the palette cascade comes from `./themePalette`, the
 * single resolver this file shares with themeFillForeground.test.ts. That
 * module's header documents this stylesheet's wrong-measurement traps
 * (partial per-component override blocks, compound selector lists) and why
 * exactly one copy of the parser exists.
 *
 * Scope: built-in palettes only. A theme pack installed from a folder or
 * created in the theme editor supplies its own tokens at runtime and is not
 * measured here. The backdrop measured is --bg-elevated, the surface the
 * issue's floor was established against.
 */
import { describe, it, expect } from 'vitest'
import { relativeLuminance, contrastRatio, parseCssColor } from '../lib/iconContrast'
import { CSS, THEMES, resolveVar } from './themePalette'

/** Sentinel that matches no [data-theme=…] selector, so resolution walks the
 *  pure `:root` cascade — the palette a theme-less <html> actually gets. */
const ROOT_ONLY = '\u0000none'

/** Luminance of a theme's token, failing LOUDLY with the theme and token named:
 *  an unparseable value (a future `var()` indirection, `color-mix(…)`, a missing
 *  declaration) must become a red test naming the culprit, never a silent skip
 *  that leaves that theme unmeasured. */
function tokenLuminance(theme: string, prop: string): number {
  const raw = resolveVar(theme, prop)
  if (raw === undefined) throw new Error(`theme ${theme}: ${prop} resolves to nothing`)
  const c = parseCssColor(raw)
  if (!c) throw new Error(`theme ${theme}: ${prop}=${raw} is not a colour this test can measure`)
  return relativeLuminance(c.r, c.g, c.b)
}

/** The thumb token, read from the stylesheet's own coarse-pointer branch. */
const COARSE = [...CSS.matchAll(/@media \(pointer: coarse\) \{\n([\s\S]*?)\n\}/g)].map(m => m[1]).join('\n')
const THUMB_TOKEN = /\.scrollbar-overlay::-webkit-scrollbar-thumb\{background:var\((--[a-zA-Z0-9_-]+)\)\}/.exec(COARSE)

describe('coarse-pointer scrollbar thumb clears 3:1 non-text contrast in every theme', () => {
  it('anchors the premise: parser found the palettes, the themes, and the thumb token', () => {
    // A regex that silently stopped matching would make the per-theme loop below
    // pass on an empty haystack. The stylesheet declares 36 theme palettes (18
    // families x 2 polarities, matching THEMES in hooks/useTheme.tsx), so the
    // floor sits at the real count rather than comfortably below it.
    expect(THUMB_TOKEN, 'coarse-pointer .scrollbar-overlay thumb rule not found').not.toBeNull()
    expect(THEMES.length, 'fewer [data-theme] names than the stylesheet declares').toBeGreaterThanOrEqual(36)
    expect(resolveVar(ROOT_ONLY, '--bg-elevated'), ':root --bg-elevated not found').toBeTruthy()
    expect(resolveVar(ROOT_ONLY, THUMB_TOKEN![1]), `:root ${THUMB_TOKEN![1]} not found`).toBeTruthy()
    expect(THEMES).toContain('kiro-dark')
    // The two themes whose base palette lives ONLY in a compound selector list —
    // the case an exact-single-selector parser silently measures against :root.
    // Their resolved backdrop must differ from the :root one, proving the
    // compound block was actually read.
    for (const light of ['light', 'amber-light']) {
      expect(THEMES).toContain(light)
      expect(resolveVar(light, '--bg-elevated'), `${light} lost its compound-block palette`)
        .not.toBe(resolveVar(ROOT_ONLY, '--bg-elevated'))
    }
  })

  it('the thumb token contrasts >= 3:1 with --bg-elevated in :root and every theme', () => {
    const token = THUMB_TOKEN![1]
    const failures: string[] = []
    for (const theme of [ROOT_ONLY, ...THEMES]) {
      const name = theme === ROOT_ONLY ? ':root' : theme
      const ratio = contrastRatio(tokenLuminance(theme, token), tokenLuminance(theme, '--bg-elevated'))
      if (ratio < 3) {
        failures.push(
          `${name}: ${token}=${resolveVar(theme, token)} vs --bg-elevated=${resolveVar(theme, '--bg-elevated')} → ${ratio.toFixed(2)}:1`,
        )
      }
    }
    expect(failures, `themes below the 3:1 non-text-contrast floor:\n${failures.join('\n')}`).toEqual([])
  })
})
