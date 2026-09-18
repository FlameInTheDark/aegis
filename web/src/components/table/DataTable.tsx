import { ReactNode, useMemo, useState } from 'react'
import { clsx } from 'clsx'
import { useQuery } from '@tanstack/react-query'
import { ArrowDown, ArrowUp, ArrowUpDown } from 'lucide-react'
import { api } from '@/lib/api'
import type { Page } from '@/types'
import { Spinner, EmptyState, ErrorState } from '@/components/ui'

export interface Column<T> {
  key: string
  header: string
  render: (row: T) => ReactNode
  sortValue?: (row: T) => string | number
  width?: string
  align?: 'left' | 'right' | 'center'
}

// SortableData converts a raw API payload into rows, tolerating null items
// (Go nil slices serialize as null) and null rows.
export function sortableRows<T>(data: unknown, transform?: (d: unknown) => T[]): T[] {
  const raw = transform ? transform(data) : (data as Page<T>)?.items
  return (Array.isArray(raw) ? raw : []).filter((r): r is T => r != null)
}

export function DataTable<T extends { id?: string }>({ columns, queryKey, path, emptyTitle, emptyHint, transform, initialSort }: {
  columns: Column<T>[]
  queryKey: string
  path: string
  emptyTitle: string
  emptyHint?: string
  transform?: (data: unknown) => T[]
  initialSort?: { key: string; dir: 'asc' | 'desc' }
}) {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: [queryKey, path],
    queryFn: () => api.get<unknown>(path),
  })
  const [sort, setSort] = useState<{ key: string; dir: 'asc' | 'desc' } | undefined>(initialSort)

  const rows = useMemo(() => {
    const base = sortableRows<T>(data, transform)
    if (!sort) return base
    const col = columns.find((c) => c.key === sort.key)
    if (!col?.sortValue) return base
    const dir = sort.dir === 'asc' ? 1 : -1
    return [...base].sort((a, b) => {
      const va = col.sortValue!(a)
      const vb = col.sortValue!(b)
      if (va < vb) return -1 * dir
      if (va > vb) return 1 * dir
      return 0
    })
  }, [data, transform, sort, columns])

  const toggleSort = (key: string) => {
    setSort((s) => (s?.key !== key ? { key, dir: 'asc' } : s.dir === 'asc' ? { key, dir: 'desc' } : undefined))
  }

  if (isLoading) return <Spinner />
  if (isError) return <ErrorState message={(error as Error).message} onRetry={() => refetch()} />
  if (rows.length === 0) return <EmptyState title={emptyTitle} hint={emptyHint} />

  return (
    <div className="overflow-x-auto">
      <table className="table-base">
        <thead>
          <tr>
            {columns.map((c) => {
              const sortable = !!c.sortValue
              const active = sort?.key === c.key
              return (
                <th
                  key={c.key}
                  style={c.width ? { width: c.width } : undefined}
                  scope="col"
                  aria-sort={active ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : undefined}
                  className={clsx(
                    sortable && 'cursor-pointer select-none hover:text-fg',
                    c.align === 'right' && 'num',
                    c.align === 'center' && 'text-center',
                  )}
                  onClick={sortable ? () => toggleSort(c.key) : undefined}
                  title={sortable ? 'Sort' : undefined}
                >
                  <span className="inline-flex items-center gap-1">
                    {c.header}
                    {sortable && (
                      active ? (
                        sort!.dir === 'asc' ? <ArrowUp size={11} aria-hidden /> : <ArrowDown size={11} aria-hidden />
                      ) : (
                        <ArrowUpDown size={11} className="opacity-40" aria-hidden />
                      )
                    )}
                  </span>
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={row.id ?? i}>
              {columns.map((c) => (
                <td key={c.key} className={c.align === 'right' ? 'num' : c.align === 'center' ? 'text-center' : undefined}>
                  {c.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
