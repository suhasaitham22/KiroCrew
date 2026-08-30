import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, within } from '@testing-library/react'

import { api } from '../api/client'
import CapabilitiesPage from '../pages/CapabilitiesPage'
import { renderWithProviders } from './helpers'

vi.mock('../pages/KiroCrewAgentsPage', () => ({ default: () => <div /> }))
vi.mock('../pages/AgentsPage', () => ({ default: () => <div /> }))
vi.mock('../pages/HooksPage', () => ({ default: () => <div /> }))
vi.mock('../pages/connections/ConnectionsPage', () => ({ default: () => <div /> }))
vi.mock('../pages/overview', () => ({
  SkillsTab: () => <div />,
  PromptsTab: () => <div />,
  SteeringTab: () => <div />,
}))
vi.mock('../components/RestartButton', () => ({ default: () => <div data-testid="restart-button" /> }))
vi.mock('../hooks/useConnectionsUi', () => ({ useConnectionsUiEnabled: () => false }))
vi.mock('../api/client', () => ({
  api: {
    projectBundles: vi.fn(),
    createProjectBundle: vi.fn(),
    addProjectBundle: vi.fn(),
    syncProjectBundle: vi.fn(),
    activateProjectBundle: vi.fn(),
    deactivateProjectBundle: vi.fn(),
  },
}))

beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear()
  vi.mocked(api.projectBundles).mockResolvedValue({ projects: [] })
})

describe('Agent Capabilities — Projects tab', () => {
  it('renders the Projects bundle manager inside Agent Capabilities', async () => {
    renderWithProviders(<CapabilitiesPage />, { route: '/capabilities?tab=projects' })

    expect(screen.getByRole('button', { name: 'Projects' })).toBeInTheDocument()
    expect(await screen.findByText('No projects yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create project' })).toBeInTheDocument()
    expect(screen.queryByTestId('restart-button')).not.toBeInTheDocument()
  })

  it('keeps a dirty Project editor open when a capability tab change is cancelled', async () => {
    const project = {
      id: '018f4f4a-760f-7a8b-a5d4-5a7e0f130d5e',
      name: 'Payments',
      description: '',
      workspace_source: 'self',
      sources: [],
      context: { agents: [], skills: [], mcp: '' },
      revision: 'one',
      registrations: [{ origin: 'local' as const, path: '/work/payments', syncable: false }],
      health: { status: 'healthy' as const, code: 'project_healthy' },
      sessions: [],
      capabilities: {
        active: false,
        trusted: false,
        review_key: '/work/payments',
        agents: 0,
        skills: 0,
        mcp_servers: 0,
        repos: 0,
        repositories: [],
      },
    }
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [project] })
    renderWithProviders(<CapabilitiesPage />, {
      route: `/capabilities?tab=projects&project=${project.id}&view=edit`,
    })

    fireEvent.change(await screen.findByLabelText('Project name'), { target: { value: 'Unsaved' } })
    fireEvent.click(screen.getByRole('button', { name: 'Skills' }))
    const dialog = await screen.findByRole('dialog', { name: 'Discard project changes?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    expect(screen.getByDisplayValue('Unsaved')).toBeInTheDocument()
  })
})
