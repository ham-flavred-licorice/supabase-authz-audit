// @ts-check
// Two adapters behind one tiny interface. Both hold a single connection, because the
// audit manages its own transaction (BEGIN ... ROLLBACK) and savepoints by hand.

/**
 * @typedef {{ rows: any[], rowCount: number }} QueryResult
 * @typedef {{
 *   kind: 'pg' | 'pglite',
 *   query: (sql: string, params?: any[]) => Promise<QueryResult>,
 *   exec: (sql: string) => Promise<void>,
 *   close: () => Promise<void>
 * }} Db
 */

/**
 * Connect to a real Postgres (Supabase, local stack, CI service container).
 * @param {string} connectionString
 * @returns {Promise<Db>}
 */
export async function connectPg(connectionString) {
  const { default: pg } = await import('pg')
  const client = new pg.Client({ connectionString })
  await client.connect()
  return {
    kind: 'pg',
    async query(sql, params = []) {
      const r = await client.query(sql, params)
      return { rows: r.rows ?? [], rowCount: r.rowCount ?? 0 }
    },
    async exec(sql) {
      await client.query(sql)
    },
    async close() {
      await client.end()
    },
  }
}

/**
 * In-process Postgres (WASM). Used by the bundled demo and the test suite so they
 * run anywhere Node runs, with no Docker and no database server.
 * @param {string} [dataDir] omit for in-memory
 * @returns {Promise<Db>}
 */
export async function connectPglite(dataDir) {
  const { PGlite } = await import('@electric-sql/pglite')
  const db = new PGlite(dataDir)
  await db.waitReady
  return {
    kind: 'pglite',
    async query(sql, params = []) {
      const r = await db.query(sql, params)
      return { rows: r.rows ?? [], rowCount: r.affectedRows ?? 0 }
    },
    async exec(sql) {
      await db.exec(sql)
    },
    async close() {
      await db.close()
    },
  }
}

/** Quote an identifier the way Postgres does. */
export function quoteIdent(name) {
  return '"' + String(name).replace(/"/g, '""') + '"'
}

/** Quote a string literal. */
export function quoteLiteral(value) {
  return "'" + String(value).replace(/'/g, "''") + "'"
}

/** Positional parameter collector: P.add(value) returns "$n". */
export class Params {
  constructor() {
    /** @type {any[]} */
    this.values = []
  }
  /** @param {any} value */
  add(value) {
    this.values.push(value)
    return '$' + this.values.length
  }
}

/**
 * Render parameterised SQL as a copy-pasteable statement for the report.
 * Long arrays are shortened; this text is for humans, it is never executed.
 * @param {string} sql
 * @param {any[]} values
 */
export function inlineParams(sql, values) {
  return sql.replace(/\$(\d+)/g, (_, n) => {
    const v = values[Number(n) - 1]
    if (v === null || v === undefined) return 'NULL'
    if (Array.isArray(v)) {
      const shown = v.slice(0, 3).map(quoteLiteral).join(', ')
      const more = v.length > 3 ? ` /* +${v.length - 3} more */` : ''
      return `ARRAY[${shown}${more}]`
    }
    return quoteLiteral(v)
  })
}
