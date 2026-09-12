import type { ExampleResponse, HealthResponse, MetaResponse } from '../types'

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `HTTP ${response.status}`
    try {
      const payload = await response.json()
      if (payload?.error) {
        message = payload.error
      }
    } catch {
      // ignore invalid JSON
    }
    throw new Error(message)
  }

  return response.json() as Promise<T>
}

export const healthApi = {
  get: async () => handleResponse<HealthResponse>(await fetch(`${API_BASE}/health`)),
}

export const exampleApi = {
  get: async () => handleResponse<ExampleResponse>(await fetch(`${API_BASE}/example`)),
}

export const metaApi = {
  get: async () => handleResponse<MetaResponse>(await fetch(`${API_BASE}/meta`)),
}
