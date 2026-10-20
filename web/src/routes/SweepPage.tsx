// `/s/:sweeper/:id`: one sweep record, never its findings (04, Views). A
// placeholder showing the record as the store holds it until the detail task
// adds duration, playbook and the trust badge.

import { useParams } from 'react-router'
import { useBoard } from '../App.tsx'
import { parseRecordId } from '../records/ids.ts'
import { parsePubky } from '../records/pubky.ts'
import type { SweepRef } from '../records/urls.ts'
import { sweepKey } from '../store/state.ts'
import { NotFound } from './NotFound.tsx'

export function SweepPage() {
  const ref = useSweepRef()
  return ref === null ? <NotFound /> : <Sweep sweepRef={ref} />
}

/** The sweep the address names, or `null` when its key or id is malformed (as BountyPage). */
function useSweepRef(): SweepRef | null {
  const params = useParams()
  const sweeper = parsePubky(params.sweeper ?? '')
  const id = parseRecordId(params.id ?? '')
  return sweeper === null || id === null ? null : { sweeper, id }
}

function Sweep({ sweepRef }: { readonly sweepRef: SweepRef }) {
  const entry = useBoard((state) => state.sweeps.get(sweepKey(sweepRef)))
  return (
    <div className="container page">
      <h1>Sweep</h1>
      <p>
        <span className="mono">{sweepRef.id}</span> by{' '}
        <span className="pubky">{sweepRef.sweeper}</span>
      </p>
      <p>{entry === undefined ? 'Not read yet.' : entry.record.status}</p>
    </div>
  )
}
