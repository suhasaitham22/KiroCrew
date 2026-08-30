import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { useNavigate } from 'react-router-dom'

import { api } from '../api/client'
import ProjectBundlesPage from '../pages/ProjectBundlesPage'
import { renderWithProviders } from './helpers'

vi.mock('../api/client', () => ({
  api: {
    projectBundles: vi.fn(),
    createProjectBundle: vi.fn(),
    addProjectBundle: vi.fn(),
    syncProjectBundle: vi.fn(),
    updateProjectBundle: vi.fn(),
    activateProjectBundle: vi.fn(),
    deactivateProjectBundle: vi.fn(),
    removeProjectBundle: vi.fn(),
    createChatSlot: vi.fn(),
    chatSlotProject: vi.fn(),
    setSlotColor: vi.fn(),
    setSlotColorHex: vi.fn(),
    deleteChatSlot: vi.fn(),
  },
}))

const localProject = {
  id: '018f4f4a-760f-7a8b-a5d4-5a7e0f130d4e',
  name: 'Payments Platform',
  description: 'Payments services and operational context.',
  editable: {
    name: 'Payments Platform',
    description: 'Payments services and operational context.',
  },
  workspace_source: 'payments-api',
  sources: [{
    id: 'payments-api',
    type: 'repo',
    url: 'https://github.com/acme/payments-api',
    default_branch: 'main',
  }],
  context: {
    agents: ['agents/*.json'],
    skills: ['skills/'],
    mcp: 'mcp.json',
  },
  revision: 'revision-one',
  registrations: [{ origin: 'local' as const, path: '/work/payments', syncable: false }],
  health: { status: 'healthy' as const, code: 'project_healthy' },
  sessions: [{
    key: 'payments-chat',
    title: 'Investigate refunds',
    messages: 4,
    running: false,
    live: true,
  }],
  capabilities: {
    active: false,
    review_key: '/work/payments',
    agents: 2,
    skills: 3,
    mcp_servers: 1,
    repos: 1,
    repositories: [],
    agent_names: ['reviewer', 'release-manager'],
    mcp_server_details: [{ name: 'docs', command: 'uvx', args: ['docs-mcp', '--readonly'] }],
  },
}

const managedProject = {
  ...localProject,
  id: '018f4f4a-760f-7a8b-a5d4-5a7e0f130d5f',
  name: 'Shared Payments',
  registrations: [{
    origin: 'managed_git' as const,
    path: '/data/projects/shared-payments',
    syncable: true,
  }],
}

function ProgrammaticNavigation() {
  const navigate = useNavigate()
  return <button onClick={() => navigate('/schedule')}>Open schedule</button>
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(api.projectBundles).mockResolvedValue({ projects: [localProject] })
  vi.mocked(api.createProjectBundle).mockResolvedValue(localProject)
  vi.mocked(api.addProjectBundle).mockResolvedValue(localProject)
  vi.mocked(api.syncProjectBundle).mockResolvedValue(managedProject)
  vi.mocked(api.updateProjectBundle).mockResolvedValue(localProject)
  vi.mocked(api.activateProjectBundle).mockResolvedValue({
    ...localProject.capabilities,
    active: true,
  })
  vi.mocked(api.deactivateProjectBundle).mockResolvedValue(localProject.capabilities)
  vi.mocked(api.removeProjectBundle).mockResolvedValue({ ok: true, id: localProject.id })
  vi.mocked(api.createChatSlot).mockResolvedValue({
    key: 'new-project-chat',
    title: 'New Session',
    messages: 0,
    running: false,
    project: '/work/payments',
    project_id: localProject.id,
  })
})

describe('Project bundles portal', () => {
  it('opens a Project from a single-column list into a focused detail view', async () => {
    renderWithProviders(<ProjectBundlesPage />)

    const project = await screen.findByRole('button', { name: /Open project Payments Platform/ })
    expect(screen.queryByRole('button', { name: 'New session' })).not.toBeInTheDocument()

    fireEvent.click(project)

    expect(await screen.findByRole('heading', { name: 'Payments Platform' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Back to projects' })).toBeInTheDocument()
    expect(screen.getByText('Payments services and operational context.')).toBeInTheDocument()
    expect(screen.getAllByText('payments-api')).toHaveLength(2)
    expect(screen.getByText('https://github.com/acme/payments-api')).toBeInTheDocument()
    expect(screen.getByText('/work/payments')).toBeInTheDocument()
    expect(screen.getByText('Healthy')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit project' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Trust and activate' })).toBeInTheDocument()
    expect(screen.getByText('Investigate refunds')).toBeInTheDocument()
    expect(screen.getByText('/work/payments')).toBeInTheDocument()
  })

  it('deep-links directly to a Project and its editor', async () => {
    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })

    expect(await screen.findByRole('heading', { name: 'Edit project' })).toBeInTheDocument()
    expect(screen.getByDisplayValue('Payments Platform')).toBeInTheDocument()
    expect(screen.getByLabelText('Description').tagName).toBe('INPUT')
  })

  it('edits the owner-only manifest values instead of redacted display text', async () => {
    vi.mocked(api.projectBundles).mockResolvedValue({
      projects: [{
        ...localProject,
        name: '[REDACTED: credential]',
        description: 'Deploy key [REDACTED: credential]',
        editable: {
          name: 'AKIAIOSFODNN7EXAMPLE',
          description: 'Deploy key AKIAIOSFODNN7EXAMPLE',
        },
      }],
    })

    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })

    expect(await screen.findByLabelText('Project name')).toHaveValue('AKIAIOSFODNN7EXAMPLE')
    expect(screen.getByLabelText('Description')).toHaveValue('Deploy key AKIAIOSFODNN7EXAMPLE')
  })

  it('guards dirty editor navigation until changes are discarded', async () => {
    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })
    fireEvent.change(await screen.findByLabelText('Project name'), {
      target: { value: 'Unsaved name' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Back to project' }))

    const dialog = await screen.findByRole('dialog', { name: 'Discard project changes?' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    expect(screen.getByDisplayValue('Unsaved name')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Back to project' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Discard changes' }))
    expect(await screen.findByRole('heading', { name: 'Payments Platform' })).toBeInTheDocument()
  })

  it('preserves unsaved edits across a background manifest refresh', async () => {
    const refreshedProject = {
      ...localProject,
      name: 'Name changed on disk',
      revision: 'revision-from-disk',
    }
    vi.mocked(api.projectBundles)
      .mockResolvedValueOnce({ projects: [localProject] })
      .mockResolvedValue({ projects: [refreshedProject] })
    const { queryClient } = renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })
    fireEvent.change(await screen.findByLabelText('Project name'), {
      target: { value: 'Unsaved local name' },
    })

    await act(async () => {
      await queryClient.invalidateQueries({ queryKey: ['project-bundles'] })
    })
    await waitFor(() => expect(api.projectBundles).toHaveBeenCalledTimes(2))

    expect(screen.getByLabelText('Project name')).toHaveValue('Unsaved local name')
  })

  it('guards dirty editor links before leaving the Projects surface', async () => {
    renderWithProviders(
      <>
        <ProjectBundlesPage />
        <a href="/chat">Leave projects</a>
      </>,
      { route: `/capabilities?tab=projects&project=${localProject.id}&view=edit` },
    )
    fireEvent.change(await screen.findByLabelText('Project name'), {
      target: { value: 'Unsaved name' },
    })
    fireEvent.click(screen.getByRole('link', { name: 'Leave projects' }))

    expect(await screen.findByRole('dialog', { name: 'Discard project changes?' })).toBeInTheDocument()
    expect(screen.getByDisplayValue('Unsaved name')).toBeInTheDocument()
  })

  it('guards dirty editor navigation initiated through the router', async () => {
    renderWithProviders(
      <>
        <ProjectBundlesPage />
        <ProgrammaticNavigation />
      </>,
      { route: `/capabilities?tab=projects&project=${localProject.id}&view=edit` },
    )
    fireEvent.change(await screen.findByLabelText('Project name'), {
      target: { value: 'Unsaved name' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Open schedule' }))

    expect(await screen.findByRole('dialog', { name: 'Discard project changes?' })).toBeInTheDocument()
    expect(screen.getByDisplayValue('Unsaved name')).toBeInTheDocument()
  })

  it('preserves unsupported source types and provider configuration when saving', async () => {
    const projectWithExtensionSource = {
      ...localProject,
      workspace_source: 'payments-api',
      sources: [
        ...localProject.sources,
        { id: 'pay-board', type: 'jira', board: 'PAY', filters: { active: true } },
      ],
    }
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [projectWithExtensionSource] })
    vi.mocked(api.updateProjectBundle).mockResolvedValue(projectWithExtensionSource)
    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })

    fireEvent.change(await screen.findByLabelText('Project name'), {
      target: { value: 'Payments Platform v2' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(api.updateProjectBundle).toHaveBeenCalled())
    expect(vi.mocked(api.updateProjectBundle).mock.calls[0]?.[1].sources).toEqual([
      localProject.sources[0],
      { id: 'pay-board', type: 'jira', board: 'PAY', filters: { active: true } },
    ])
  })

  it('offers only repository sources as the working repository', async () => {
    const projectWithExtensionSource = {
      ...localProject,
      sources: [
        ...localProject.sources,
        { id: 'pay-board', type: 'jira', board: 'PAY' },
      ],
    }
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [projectWithExtensionSource] })
    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })

    const picker = await screen.findByLabelText('Working repository')
    fireEvent.click(picker)
    expect(screen.getByRole('option', { name: 'payments-api' })).toBeInTheDocument()
    expect(screen.queryByRole('option', { name: 'pay-board' })).not.toBeInTheDocument()
  })

  it('renders only repository sources in detail when provider data contains objects', async () => {
    const projectWithExtensionSource = {
      ...localProject,
      sources: [
        ...localProject.sources,
        { id: 'pay-board', type: 'jira', url: { board: 'PAY' } },
      ],
    }
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [projectWithExtensionSource] })
    renderWithProviders(<ProjectBundlesPage />)

    fireEvent.click(await screen.findByRole('button', { name: /Open project Payments Platform/ }))

    expect(screen.getByText('https://github.com/acme/payments-api')).toBeInTheDocument()
    expect(screen.queryByText('pay-board')).not.toBeInTheDocument()
  })

  it('does not crash when a malformed repository URL reaches the editor', async () => {
    const malformed = {
      ...localProject,
      sources: [{ id: 'payments-api', type: 'repo', url: 7 }],
    }
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [malformed] })
    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })

    expect(await screen.findByRole('button', { name: 'Save changes' })).toBeDisabled()
    expect(screen.getByRole('alert')).toHaveTextContent('Every repository needs an ID and URL.')
  })

  it('explains duplicate repository ids instead of silently disabling save', async () => {
    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })
    fireEvent.click(await screen.findByRole('button', { name: 'Add repository' }))
    fireEvent.change(screen.getByLabelText('Repository ID 2'), {
      target: { value: 'payments-api' },
    })
    fireEvent.change(screen.getByLabelText('Repository URL or path 2'), {
      target: { value: 'https://github.com/acme/payments-api-copy' },
    })

    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    expect(screen.getByRole('alert')).toHaveTextContent('Repository IDs must be unique.')
  })

  it('trims a renamed working repository id before saving', async () => {
    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })
    fireEvent.change(await screen.findByLabelText('Repository ID 1'), {
      target: { value: 'payments-api ' },
    })
    fireEvent.change(screen.getByLabelText('Description'), {
      target: { value: 'Updated description.' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => expect(api.updateProjectBundle).toHaveBeenCalled())
    expect(vi.mocked(api.updateProjectBundle).mock.calls[0]?.[1].workspace_source).toBe('payments-api')
  })

  it('edits every persisted Project field in one full-width form', async () => {
    const updatedProject = {
      ...localProject,
      name: 'Checkout Platform',
      description: 'Checkout services.',
      workspace_source: 'checkout-web',
      sources: [
        {
          id: 'payments-api',
          type: 'repo',
          url: 'https://github.com/acme/payments-api',
          default_branch: 'main',
        },
        {
          id: 'checkout-web',
          type: 'repo',
          url: 'https://github.com/acme/checkout-web',
          default_branch: 'trunk',
        },
      ],
      context: {
        agents: ['agents/reviewer.json'],
        skills: ['skills/checkout/'],
        mcp: 'config/mcp.json',
      },
      revision: 'revision-two',
    }
    vi.mocked(api.projectBundles)
      .mockResolvedValueOnce({ projects: [localProject] })
      .mockResolvedValue({ projects: [updatedProject] })
    vi.mocked(api.updateProjectBundle).mockResolvedValue(updatedProject)
    renderWithProviders(<ProjectBundlesPage />)

    fireEvent.click(await screen.findByRole('button', { name: /Open project Payments Platform/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Edit project' }))
    fireEvent.change(screen.getByLabelText('Project name'), { target: { value: 'Checkout Platform' } })
    fireEvent.change(screen.getByLabelText('Description'), { target: { value: 'Checkout services.' } })
    fireEvent.change(screen.getByLabelText('Agent path 1'), { target: { value: 'agents/reviewer.json' } })
    fireEvent.change(screen.getByLabelText('Skill path 1'), { target: { value: 'skills/checkout/' } })
    fireEvent.change(screen.getByLabelText('MCP configuration path'), { target: { value: 'config/mcp.json' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add repository' }))
    fireEvent.change(screen.getByLabelText('Repository ID 2'), { target: { value: 'checkout-web' } })
    fireEvent.change(screen.getByLabelText('Repository URL or path 2'), { target: { value: 'https://github.com/acme/checkout-web' } })
    fireEvent.change(screen.getByLabelText('Default branch 2'), { target: { value: 'trunk' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }))

    await waitFor(() => {
      expect(api.updateProjectBundle).toHaveBeenCalledWith(localProject.id, {
        revision: 'revision-one',
        name: 'Checkout Platform',
        description: 'Checkout services.',
        workspace_source: 'payments-api',
        sources: [
          {
            id: 'payments-api',
            type: 'repo',
            url: 'https://github.com/acme/payments-api',
            default_branch: 'main',
          },
          {
            id: 'checkout-web',
            type: 'repo',
            url: 'https://github.com/acme/checkout-web',
            default_branch: 'trunk',
          },
        ],
        context: {
          agents: ['agents/reviewer.json'],
          skills: ['skills/checkout/'],
          mcp: 'config/mcp.json',
        },
      })
    })
    expect(await screen.findByRole('heading', { name: 'Checkout Platform' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Save changes' })).not.toBeInTheDocument()
  })

  it('starts a session with the Project identity in the create request', async () => {
    renderWithProviders(<ProjectBundlesPage />)

    fireEvent.click(await screen.findByRole('button', { name: /Open project Payments Platform/ }))
    fireEvent.click(screen.getByRole('button', { name: 'New session' }))

    await waitFor(() => {
      expect(api.createChatSlot).toHaveBeenCalledWith(
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        localProject.id,
      )
    })
  })

  it('explains how to populate an empty registry', async () => {
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [] })

    renderWithProviders(<ProjectBundlesPage />)

    expect(await screen.findByText('No projects yet')).toBeInTheDocument()
    expect(screen.getByText('Create a local bundle or add one from a folder or Git URL.')).toBeInTheDocument()
  })

  it('creates a local bundle and refreshes the portal list', async () => {
    vi.mocked(api.projectBundles)
      .mockResolvedValueOnce({ projects: [] })
      .mockResolvedValue({ projects: [localProject] })

    renderWithProviders(<ProjectBundlesPage />)
    await screen.findByText('No projects yet')
    fireEvent.click(screen.getByRole('button', { name: 'Create project' }))
    fireEvent.change(screen.getByLabelText('Project name'), {
      target: { value: 'Payments Platform' },
    })
    fireEvent.change(screen.getByLabelText('Bundle folder'), {
      target: { value: '/work/payments' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Create bundle' }))

    expect(await screen.findByRole('button', { name: /Open project Payments Platform/ })).toBeInTheDocument()
  })

  it('adds an existing folder or Git URL and refreshes the portal list', async () => {
    vi.mocked(api.projectBundles)
      .mockResolvedValueOnce({ projects: [] })
      .mockResolvedValue({ projects: [localProject] })

    renderWithProviders(<ProjectBundlesPage />)
    await screen.findByText('No projects yet')
    fireEvent.click(screen.getByRole('button', { name: 'Add project' }))
    fireEvent.change(screen.getByLabelText('Folder or Git URL'), {
      target: { value: '/work/payments' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add bundle' }))

    expect(await screen.findByRole('button', { name: /Open project Payments Platform/ })).toBeInTheDocument()
  })

  it('syncs managed Git projects and confirms completion', async () => {
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [managedProject] })

    renderWithProviders(<ProjectBundlesPage />)
    fireEvent.click(await screen.findByRole('button', { name: /Open project Shared Payments/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Sync project' }))

    expect(await screen.findByText('Project synced.')).toBeInTheDocument()
  })

  it('offers recovery for an unavailable Git Project and explains why sessions are blocked', async () => {
    const unavailable = {
      ...managedProject,
      health: { status: 'unavailable' as const, code: 'project_manifest_unavailable' },
    }
    vi.mocked(api.projectBundles).mockResolvedValue({ projects: [unavailable] })

    renderWithProviders(<ProjectBundlesPage />)
    fireEvent.click(await screen.findByRole('button', { name: /Open project Shared Payments/ }))

    expect(screen.getByRole('alert')).toHaveTextContent('Project files are unavailable')
    expect(screen.getByRole('button', { name: 'Retry sync' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'New session' })).toBeDisabled()
  })

  it('explains which files removal preserves', async () => {
    vi.mocked(api.projectBundles)
      .mockResolvedValueOnce({ projects: [localProject] })
      .mockResolvedValue({ projects: [] })
    renderWithProviders(<ProjectBundlesPage />)
    fireEvent.click(await screen.findByRole('button', { name: /Open project Payments Platform/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Remove from Kiro Crew' }))

    expect(await screen.findByText(
      'Folders you added stay on disk. Kiro Crew removes only storage it created for this project.',
    )).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Remove project' }))

    await waitFor(() => expect(api.removeProjectBundle).toHaveBeenCalledWith(localProject.id))
    expect(await screen.findByText('No projects yet')).toBeInTheDocument()
  })

  it('activates bundled capabilities after an explicit trust action', async () => {
    vi.mocked(api.projectBundles)
      .mockResolvedValueOnce({ projects: [localProject] })
      .mockResolvedValue({
        projects: [{
          ...localProject,
          capabilities: { ...localProject.capabilities, active: true },
        }],
      })

    renderWithProviders(<ProjectBundlesPage />)
    fireEvent.click(await screen.findByRole('button', { name: /Open project Payments Platform/ }))
    expect(screen.getByText('reviewer')).toBeInTheDocument()
    expect(screen.getByText('release-manager')).toBeInTheDocument()
    expect(screen.getByText('docs')).toBeInTheDocument()
    expect(screen.getByText('"uvx" "docs-mcp" "--readonly"')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Trust and activate' }))

    expect(api.activateProjectBundle).not.toHaveBeenCalled()
    expect(await screen.findByRole('dialog', { name: 'Trust and activate this project?' })).toBeInTheDocument()
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Trust and activate' }))

    await waitFor(() => {
      expect(api.activateProjectBundle).toHaveBeenCalledWith(localProject.id, '/work/payments')
    })
    expect(await screen.findByRole('button', { name: 'Deactivate capabilities' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit project' })).toBeDisabled()
  })

  it('does not open the manifest editor for an active Project deep link', async () => {
    vi.mocked(api.projectBundles).mockResolvedValue({
      projects: [{
        ...localProject,
        capabilities: { ...localProject.capabilities, active: true },
      }],
    })

    renderWithProviders(<ProjectBundlesPage />, {
      route: `/capabilities?tab=projects&project=${localProject.id}&view=edit`,
    })

    expect(await screen.findByRole('heading', { name: 'Payments Platform' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Edit project' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit project' })).toBeDisabled()
  })

  it('shows resolved capability counts and materialized repository paths', async () => {
    vi.mocked(api.projectBundles).mockResolvedValue({
      projects: [{
        ...localProject,
        capabilities: {
          ...localProject.capabilities,
          active: true,
          repositories: [{ source_id: 'payments-api', path: '/managed/projects/payments-api' }],
        },
      }],
    })
    renderWithProviders(<ProjectBundlesPage />)
    fireEvent.click(await screen.findByRole('button', { name: /Open project Payments Platform/ }))

    expect(screen.getByText('/managed/projects/payments-api')).toBeInTheDocument()
    expect(screen.getAllByText('payments-api', { selector: '.font-medium' })).toHaveLength(2)
    expect(screen.getAllByText('2')).not.toHaveLength(0)
    expect(screen.getAllByText('3')).not.toHaveLength(0)
  })
})
