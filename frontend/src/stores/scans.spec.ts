import { vi, describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// Mock the API client module
vi.mock('@/api/client', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: 'http://test' },
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
}))

// Mock the tenant store dependency
vi.mock('./tenant', () => ({
  useTenantStore: vi.fn(() => ({
    currentTenantId: 1,
  })),
}))

import apiClient from '@/api/client'
import { useTenantStore } from './tenant'
import {
  useScanStore,
  SCAN_TIERS,
  type Project,
  type ScanRun,
  type PhaseProgress,
  type TaskResponse,
} from './scans'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeProject(overrides: Partial<Project> = {}): Project {
  return {
    id: 1,
    tenant_id: 1,
    name: 'ACME Recon',
    description: 'Reconnaissance for ACME Corp',
    seeds: [{ type: 'domain', value: 'acme.com' }],
    settings: null,
    created_at: '2026-02-20T10:00:00Z',
    updated_at: '2026-02-20T10:00:00Z',
    ...overrides,
  }
}

function makeScanRun(overrides: Partial<ScanRun> = {}): ScanRun {
  return {
    id: 1,
    project_id: 1,
    profile_id: null,
    tenant_id: 1,
    status: 'pending',
    triggered_by: 'manual',
    started_at: null,
    completed_at: null,
    stats: null,
    error_message: null,
    celery_task_id: 'task-abc-123',
    created_at: '2026-02-28T10:00:00Z',
    duration_seconds: null,
    ...overrides,
  }
}

function makePhaseProgress(overrides: Partial<PhaseProgress> = {}): PhaseProgress {
  return {
    id: 1,
    scan_run_id: 1,
    phase: 'subfinder',
    status: 'completed',
    started_at: '2026-02-28T10:00:00Z',
    completed_at: '2026-02-28T10:01:00Z',
    stats: { count: 42 },
    error_message: null,
    duration_seconds: 60,
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('scans store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  // -----------------------------------------------------------------------
  // SCAN_TIERS constant
  // -----------------------------------------------------------------------
  describe('SCAN_TIERS', () => {
    it('has exactly 3 tiers', () => {
      expect(SCAN_TIERS).toHaveLength(3)
    })

    it('contains Safe, Moderate, and Aggressive tiers', () => {
      const names = SCAN_TIERS.map(t => t.name)
      expect(names).toEqual(['Safe', 'Moderate', 'Aggressive'])
    })

    it('tier numbers are 1, 2, 3', () => {
      expect(SCAN_TIERS.map(t => t.tier)).toEqual([1, 2, 3])
    })

    it('each tier has description, ports, and rate', () => {
      for (const tier of SCAN_TIERS) {
        expect(tier.description).toBeTruthy()
        expect(tier.ports).toBeTruthy()
        expect(tier.rate).toBeTruthy()
      }
    })
  })

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------
  describe('initial state', () => {
    it('has empty collections and default loading states', () => {
      const store = useScanStore()
      expect(store.projects).toEqual([])
      expect(store.selectedProject).toBeNull()
      expect(store.scanRuns).toEqual([])
      expect(store.currentScanRun).toBeNull()
      expect(store.phaseProgress).toEqual([])
      expect(store.isLoadingProjects).toBe(false)
      expect(store.isLoadingRuns).toBe(false)
      expect(store.isLoadingProgress).toBe(false)
      expect(store.error).toBe('')
    })
  })

  // -----------------------------------------------------------------------
  // fetchProjects
  // -----------------------------------------------------------------------
  describe('fetchProjects', () => {
    it('loads project list from array response', async () => {
      const projects = [makeProject({ id: 1 }), makeProject({ id: 2, name: 'Other' })]
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: projects })

      const store = useScanStore()
      await store.fetchProjects()

      expect(store.projects).toHaveLength(2)
      expect(store.projects[0].name).toBe('ACME Recon')
      expect(store.isLoadingProjects).toBe(false)
    })

    it('loads project list from items envelope response', async () => {
      const projects = [makeProject({ id: 1 })]
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: { items: projects } })

      const store = useScanStore()
      await store.fetchProjects()

      expect(store.projects).toHaveLength(1)
    })

    it('defaults to empty array for unexpected response shape', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: {} })

      const store = useScanStore()
      await store.fetchProjects()

      expect(store.projects).toEqual([])
    })

    it('sets loading state during fetch', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: [] })

      const store = useScanStore()
      const promise = store.fetchProjects()

      expect(store.isLoadingProjects).toBe(true)
      await promise
      expect(store.isLoadingProjects).toBe(false)
    })

    it('calls correct API endpoint', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: [] })

      const store = useScanStore()
      await store.fetchProjects()

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/projects',
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      )
    })

    it('sets error on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Connection refused'))

      const store = useScanStore()
      await store.fetchProjects()

      expect(store.error).toBe('Connection refused')
      expect(store.isLoadingProjects).toBe(false)
    })

    it('returns early when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useScanStore()
      await store.fetchProjects()

      expect(store.error).toBe('No tenant selected')
      expect(apiClient.get).not.toHaveBeenCalled()
    })

    it('silently ignores CanceledError', async () => {
      const err = new Error('canceled')
      err.name = 'CanceledError'
      vi.mocked(apiClient.get).mockRejectedValueOnce(err)

      const store = useScanStore()
      await store.fetchProjects()

      expect(store.error).toBe('')
    })

    it('aborts previous fetchProjects request', async () => {
      let firstSignal: AbortSignal | undefined

      vi.mocked(apiClient.get)
        .mockImplementationOnce((_url, config) => {
          firstSignal = config?.signal as AbortSignal
          return new Promise(() => {})
        })
        .mockImplementationOnce(() => Promise.resolve({ data: [] }))

      const store = useScanStore()
      store.fetchProjects() // Fire and forget first
      await store.fetchProjects()

      expect(firstSignal?.aborted).toBe(true)
    })
  })

  // -----------------------------------------------------------------------
  // createProject
  // -----------------------------------------------------------------------
  describe('createProject', () => {
    it('creates project and adds to list', async () => {
      const newProject = makeProject({ id: 10, name: 'New Project' })
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: newProject })

      const store = useScanStore()
      store.projects = [makeProject({ id: 1 })]

      const result = await store.createProject({
        name: 'New Project',
        description: 'desc',
        seeds: [{ type: 'domain', value: 'example.com' }],
      })

      expect(result).toEqual(newProject)
      expect(store.projects).toHaveLength(2)
      expect(store.projects[1].name).toBe('New Project')
    })

    it('calls correct endpoint with payload', async () => {
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: makeProject() })

      const store = useScanStore()
      const payload = {
        name: 'Test',
        description: 'desc',
        seeds: [{ type: 'domain', value: 'test.com' }],
      }
      await store.createProject(payload)

      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/tenants/1/projects',
        payload
      )
    })

    it('returns null on error', async () => {
      vi.mocked(apiClient.post).mockRejectedValueOnce(new Error('Validation failed'))

      const store = useScanStore()
      const result = await store.createProject({
        name: '',
        description: '',
        seeds: [],
      })

      expect(result).toBeNull()
      expect(store.error).toBe('Validation failed')
    })

    it('returns null when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useScanStore()
      const result = await store.createProject({
        name: 'Test',
        description: '',
        seeds: [],
      })

      expect(result).toBeNull()
      expect(store.error).toBe('No tenant selected')
    })
  })

  // -----------------------------------------------------------------------
  // fetchScanRuns
  // -----------------------------------------------------------------------
  describe('fetchScanRuns', () => {
    it('loads scan runs for a project', async () => {
      const runs = [
        makeScanRun({ id: 1, status: 'completed' }),
        makeScanRun({ id: 2, status: 'running' }),
      ]
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: runs })

      const store = useScanStore()
      await store.fetchScanRuns(1)

      expect(store.scanRuns).toHaveLength(2)
      expect(store.isLoadingRuns).toBe(false)
    })

    it('handles items envelope response', async () => {
      const runs = [makeScanRun({ id: 1 })]
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: { items: runs } })

      const store = useScanStore()
      await store.fetchScanRuns(1)

      expect(store.scanRuns).toHaveLength(1)
    })

    it('calls correct URL with project id', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: [] })

      const store = useScanStore()
      await store.fetchScanRuns(42)

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/projects/42/scans',
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      )
    })

    it('sets error on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Failed'))

      const store = useScanStore()
      await store.fetchScanRuns(1)

      expect(store.error).toBe('Failed')
      expect(store.isLoadingRuns).toBe(false)
    })

    it('aborts previous fetchScanRuns request', async () => {
      let firstSignal: AbortSignal | undefined

      vi.mocked(apiClient.get)
        .mockImplementationOnce((_url, config) => {
          firstSignal = config?.signal as AbortSignal
          return new Promise(() => {})
        })
        .mockImplementationOnce(() => Promise.resolve({ data: [] }))

      const store = useScanStore()
      store.fetchScanRuns(1)
      await store.fetchScanRuns(2)

      expect(firstSignal?.aborted).toBe(true)
    })
  })

  // -----------------------------------------------------------------------
  // fetchScanRun (single)
  // -----------------------------------------------------------------------
  describe('fetchScanRun', () => {
    it('fetches a single scan run by id', async () => {
      const run = makeScanRun({ id: 5, status: 'running' })
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: run })

      const store = useScanStore()
      await store.fetchScanRun(5)

      expect(store.currentScanRun).toEqual(run)
      expect(apiClient.get).toHaveBeenCalledWith('/api/v1/tenants/1/scans/5')
    })

    it('sets error on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Not Found'))

      const store = useScanStore()
      await store.fetchScanRun(999)

      expect(store.error).toBe('Not Found')
    })
  })

  // -----------------------------------------------------------------------
  // triggerScan
  // -----------------------------------------------------------------------
  describe('triggerScan', () => {
    it('triggers a scan and returns the new run', async () => {
      const taskResponse: TaskResponse = {
        task_id: 'task-xyz',
        status: 'accepted',
        message: 'Scan queued',
        data: { scan_run_id: 10 },
      }
      const scanRun = makeScanRun({ id: 10, status: 'pending' })

      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: taskResponse })
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: scanRun })

      const store = useScanStore()
      const result = await store.triggerScan(1, 2)

      expect(result).toEqual(scanRun)
      expect(store.scanRuns[0].id).toBe(10)
      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/tenants/1/projects/1/scans',
        { triggered_by: 'manual', scan_tier: 2 }
      )
    })

    it('uses tier 1 by default', async () => {
      const taskResponse: TaskResponse = {
        task_id: 'task-xyz',
        status: 'accepted',
        message: 'Scan queued',
        data: { scan_run_id: 10 },
      }
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: taskResponse })
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: makeScanRun({ id: 10 }) })

      const store = useScanStore()
      await store.triggerScan(1)

      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/tenants/1/projects/1/scans',
        { triggered_by: 'manual', scan_tier: 1 }
      )
    })

    it('falls back to fetchScanRuns when task data has no scan_run_id', async () => {
      const taskResponse: TaskResponse = {
        task_id: 'task-xyz',
        status: 'accepted',
        message: 'Scan queued',
        data: null,
      }
      const runs = [makeScanRun({ id: 20 })]

      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: taskResponse })
      // fetchScanRuns call
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: runs })

      const store = useScanStore()
      const result = await store.triggerScan(5)

      expect(result).toEqual(runs[0])
      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/projects/5/scans',
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      )
    })

    it('returns null on error', async () => {
      vi.mocked(apiClient.post).mockRejectedValueOnce(new Error('Rate limited'))

      const store = useScanStore()
      const result = await store.triggerScan(1)

      expect(result).toBeNull()
      expect(store.error).toBe('Rate limited')
    })

    it('returns null when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useScanStore()
      const result = await store.triggerScan(1)

      expect(result).toBeNull()
      expect(store.error).toBe('No tenant selected')
    })
  })

  // -----------------------------------------------------------------------
  // fetchProgress
  // -----------------------------------------------------------------------
  describe('fetchProgress', () => {
    it('fetches phase-level progress for a scan run', async () => {
      const scanRun = makeScanRun({ id: 3, status: 'running' })
      const phases: PhaseProgress[] = [
        makePhaseProgress({ id: 1, phase: 'subfinder', status: 'completed' }),
        makePhaseProgress({ id: 2, phase: 'httpx', status: 'running' }),
        makePhaseProgress({ id: 3, phase: 'nuclei', status: 'pending' }),
      ]

      vi.mocked(apiClient.get).mockResolvedValueOnce({
        data: { scan_run: scanRun, phases },
      })

      const store = useScanStore()
      await store.fetchProgress(3)

      expect(store.currentScanRun).toEqual(scanRun)
      expect(store.phaseProgress).toHaveLength(3)
      expect(store.phaseProgress[0].phase).toBe('subfinder')
      expect(store.phaseProgress[1].status).toBe('running')
      expect(store.isLoadingProgress).toBe(false)
    })

    it('sets loading state during fetch', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({
        data: { scan_run: makeScanRun(), phases: [] },
      })

      const store = useScanStore()
      const promise = store.fetchProgress(1)

      expect(store.isLoadingProgress).toBe(true)
      await promise
      expect(store.isLoadingProgress).toBe(false)
    })

    it('calls correct URL', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({
        data: { scan_run: makeScanRun(), phases: [] },
      })

      const store = useScanStore()
      await store.fetchProgress(7)

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/scans/7/progress'
      )
    })

    it('sets error on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Timeout'))

      const store = useScanStore()
      await store.fetchProgress(1)

      expect(store.error).toBe('Timeout')
      expect(store.isLoadingProgress).toBe(false)
    })

    it('returns early when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useScanStore()
      await store.fetchProgress(1)

      expect(store.error).toBe('No tenant selected')
      expect(apiClient.get).not.toHaveBeenCalled()
    })
  })

  // -----------------------------------------------------------------------
  // cancelScan
  // -----------------------------------------------------------------------
  describe('cancelScan', () => {
    it('cancels a scan and updates local state', async () => {
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: { status: 'cancelled' } })

      const store = useScanStore()
      store.scanRuns = [
        makeScanRun({ id: 1, status: 'running' }),
        makeScanRun({ id: 2, status: 'pending' }),
      ]
      store.currentScanRun = makeScanRun({ id: 1, status: 'running' })

      const result = await store.cancelScan(1)

      expect(result).toBe(true)
      expect(store.currentScanRun?.status).toBe('cancelled')
      expect(store.scanRuns[0].status).toBe('cancelled')
      // Second scan run should be untouched
      expect(store.scanRuns[1].status).toBe('pending')
    })

    it('calls correct cancel endpoint', async () => {
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: {} })

      const store = useScanStore()
      await store.cancelScan(42)

      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/tenants/1/scans/42/cancel'
      )
    })

    it('does not update currentScanRun when ids differ', async () => {
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: {} })

      const store = useScanStore()
      store.currentScanRun = makeScanRun({ id: 99, status: 'running' })

      await store.cancelScan(1)

      expect(store.currentScanRun?.status).toBe('running')
    })

    it('returns false on error', async () => {
      vi.mocked(apiClient.post).mockRejectedValueOnce(new Error('Cannot cancel'))

      const store = useScanStore()
      const result = await store.cancelScan(1)

      expect(result).toBe(false)
      expect(store.error).toBe('Cannot cancel')
    })

    it('returns false when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useScanStore()
      const result = await store.cancelScan(1)

      expect(result).toBe(false)
      expect(store.error).toBe('No tenant selected')
    })
  })

  // -----------------------------------------------------------------------
  // selectProject
  // -----------------------------------------------------------------------
  describe('selectProject', () => {
    it('sets selectedProject', () => {
      const store = useScanStore()
      const project = makeProject({ id: 5 })

      store.selectProject(project)

      expect(store.selectedProject).toEqual(project)
    })
  })

  // -----------------------------------------------------------------------
  // clearError
  // -----------------------------------------------------------------------
  describe('clearError', () => {
    it('resets the error string', () => {
      const store = useScanStore()
      store.error = 'previous error'

      store.clearError()

      expect(store.error).toBe('')
    })
  })
})
