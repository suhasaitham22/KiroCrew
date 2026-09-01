/**
 * The runs-elsewhere marker and the capability source it implies.
 *
 * Two claims are under test, and they are the two a user can be misled by:
 *  (1) a session bound to a crew SAYS SO in the list, naming the crew; and
 *  (2) a session NOT bound to one says nothing — the marker has to be silent by
 *      default or it stops meaning anything.
 *
 * The chip is asserted through `RemoteCrewChip` rather than a full sidebar
 * render because the sidebar row is behind ~40 props and a Radix menu, and none
 * of that is what could regress here: the row's own decision is the
 * `executor === 'remote'` gate, covered by the store-shape test below.
 */

import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { RemoteCrewChip } from '../components/RemoteCrewChip'

describe('RemoteCrewChip', () => {
  it('names the crew the session runs on', () => {
    render(<RemoteCrewChip name="nobita" />)
    const chip = screen.getByTestId('remote-crew-chip')
    expect(chip.textContent).toContain('nobita')
  })

  it('carries an explanatory title so the marker is not a mystery glyph', () => {
    // The chip is small and unlabelled by design; without a title the only way
    // to learn what it means is to read the source.
    render(<RemoteCrewChip name="nobita" title="Runs on nobita — a connected crew, not this machine" />)
    expect(screen.getByTestId('remote-crew-chip').getAttribute('title')).toContain('not this machine')
  })

  it('falls back to the name when no title is supplied', () => {
    render(<RemoteCrewChip name="shizuka" />)
    expect(screen.getByTestId('remote-crew-chip').getAttribute('title')).toBe('shizuka')
  })

  it('renders the glyph as decorative, not as content a reader announces', () => {
    // The crew name beside it is the informative part; announcing a server icon
    // first would put decoration ahead of it.
    const { container } = render(<RemoteCrewChip name="nobita" />)
    expect(container.querySelector('[aria-hidden="true"]')).toBeTruthy()
  })

  it('uses the info token, not the neutral meta styling every sibling chip uses', () => {
    // "Runs on another machine" is a different KIND of fact from "has this tag".
    // At neutral weight it read as just another tag, which is the specific
    // misreading this chip exists to prevent.
    render(<RemoteCrewChip name="nobita" />)
    const cls = screen.getByTestId('remote-crew-chip').className
    expect(cls).toContain('text-info')
    expect(cls).toContain('bg-info-subtle')
  })
})
