import { describe, expect, it } from 'vitest'
import { assertProductionBuildEnv, networkFromEnv } from './network.ts'

describe('networkFromEnv', () => {
  it('picks the testnet only for exactly "1" in a non-production build', () => {
    expect(networkFromEnv({ PROD: false, VITE_PUBKY_TESTNET: '1' })).toBe('testnet')
  })

  it.each(['0', '', 'true', ' 1', '1 ', 'yes'])(
    'stays on production for VITE_PUBKY_TESTNET=%j',
    (value) => {
      expect(networkFromEnv({ PROD: false, VITE_PUBKY_TESTNET: value })).toBe('production')
    },
  )

  it('stays on production when the variable is unset', () => {
    expect(networkFromEnv({ PROD: false })).toBe('production')
  })

  it('never picks the testnet in a production bundle, even with "1"', () => {
    expect(networkFromEnv({ PROD: true, VITE_PUBKY_TESTNET: '1' })).toBe('production')
  })
})

describe('assertProductionBuildEnv', () => {
  it.each(['1', '0', ''])('refuses a production build with VITE_PUBKY_TESTNET=%j', (value) => {
    expect(() => assertProductionBuildEnv('production', { VITE_PUBKY_TESTNET: value })).toThrow(
      /VITE_PUBKY_TESTNET must be unset/,
    )
  })

  it('passes a production build only when the variable is absent', () => {
    expect(() => assertProductionBuildEnv('production', {})).not.toThrow()
  })

  it('leaves the development server and the test runner free to opt in', () => {
    expect(() => assertProductionBuildEnv('development', { VITE_PUBKY_TESTNET: '1' })).not.toThrow()
    expect(() => assertProductionBuildEnv('test', { VITE_PUBKY_TESTNET: '1' })).not.toThrow()
  })
})
