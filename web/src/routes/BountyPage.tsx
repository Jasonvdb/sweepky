// `/b/:owner/:id`: one bounty (04, Views). A placeholder showing the record
// as the store holds it until the detail task draws targets, sweeps and
// credits.

import { useParams } from 'react-router'
import { useBoard } from '../App.tsx'
import { parseRecordId } from '../records/ids.ts'
import { parsePubky } from '../records/pubky.ts'
import type { BountyRef } from '../records/urls.ts'
import { bountyKey } from '../store/state.ts'
import { NotFound } from './NotFound.tsx'

export function BountyPage() {
  const ref = useBountyRef()
  return ref === null ? <NotFound /> : <Bounty bountyRef={ref} />
}

/**
 * The bounty the address names, or `null` when its key or id is malformed.
 * The address is anyone's to type, so it is parsed like any other untrusted
 * text: the key raw or `pubky`-prefixed, both kept raw, the id canonical.
 */
function useBountyRef(): BountyRef | null {
  const params = useParams()
  const owner = parsePubky(params.owner ?? '')
  const id = parseRecordId(params.id ?? '')
  return owner === null || id === null ? null : { owner, id }
}

function Bounty({ bountyRef }: { readonly bountyRef: BountyRef }) {
  const entry = useBoard((state) => state.bounties.get(bountyKey(bountyRef)))
  return (
    <div className="container page">
      <h1>Bounty</h1>
      <p>
        <span className="mono">{bountyRef.id}</span> by{' '}
        <span className="pubky">{bountyRef.owner}</span>
      </p>
      {/* React escapes text, so a stranger's title cannot become markup. */}
      <p>{entry === undefined ? 'Not read yet.' : entry.record.title}</p>
    </div>
  )
}
