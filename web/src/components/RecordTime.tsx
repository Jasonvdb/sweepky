// A time a record gives, as a `<time>` element. Strangers choose their
// records' ids and times, and an id can encode a time past year 275760, the
// last a `Date` can hold: printing such a Date throws a RangeError, which
// would take the whole board down. So a time no Date can hold renders as
// nothing at all.

export function RecordTime({ ms }: { readonly ms: number }) {
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return null
  return (
    <time className="record-time" dateTime={date.toISOString()}>
      {date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}
    </time>
  )
}
