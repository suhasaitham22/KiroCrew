/**
 * Shared theme-palette cascade resolver for tests that measure `index.css`
 * source text (themeFillForeground.test.ts, scrollbarThumbContrast.test.ts).
 *
 * The CSS is parsed rather than rendered because jsdom resolves no cascade: it
 * would report every var as empty and a consumer suite would pass vacuously.
 *
 * One copy on purpose: this stylesheet has documented wrong-measurement traps
 * (a naive one-block-per-name `matchAll` reads partial per-component override
 * blocks — kiro-dark alone appears in 11 top-level selectors — and an
 * exact-single-selector parser misses compound lists like
 * `[data-theme="light"],[data-theme="amber-light"]{…}`, silently measuring
 * those themes against the `:root` dark palette). Two divergent copies of the
 * parser would re-open those traps the next time a selector shape changes,
 * with only one test noticing.
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

export const CSS = readFileSync(resolve(__dirname, '../index.css'), 'utf8')

/** Top-level rules, in document order: `[selector list] { decls }`. */
const RULES: { selectors: string[]; decls: Map<string, string> }[] = []
for (const m of CSS.matchAll(/^([^{}\n][^{}]*)\{([^{}]*)\}/gm)) {
  const decls = new Map<string, string>()
  for (const d of m[2].matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) decls.set(d[1], d[2].trim())
  RULES.push({ selectors: m[1].split(',').map((s) => s.trim()), decls })
}

/** Every theme name any `[data-theme="…"]` selector mentions, sorted. */
export const THEMES = [...new Set([...CSS.matchAll(/\[data-theme="([^"]+)"\]/g)].map((m) => m[1]))].sort()

/**
 * The value a theme actually gets for `prop`.
 *
 * A theme that omits a token does NOT fall back to nothing: the base rule is
 * keyed on `:root`, which matches `<html>` whatever the theme is, so the
 * dark-default value applies. Equal specificity means later wins.
 */
export function resolveVar(theme: string, prop: string): string | undefined {
  let value: string | undefined
  for (const rule of RULES) {
    const hit = rule.selectors.some((s) => s === ':root' || s === `[data-theme="${theme}"]`)
    if (hit && rule.decls.has(prop)) value = rule.decls.get(prop)
  }
  return value
}
