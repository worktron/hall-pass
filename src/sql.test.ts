import { describe, test, expect } from "bun:test"
import { extractSqlFromArgs, extractSqlFromPsql, isSqlReadOnly } from "./sql.ts"

describe("extractSqlFromArgs", () => {
  describe("psql", () => {
    test("-c flag", () => {
      const args = ["psql", "postgres://user:pass@localhost:5433/db", "-t", "-c", "SELECT * FROM users"]
      expect(extractSqlFromArgs("psql", args)).toBe("SELECT * FROM users")
    })

    test("--command flag", () => {
      const args = ["psql", "--command", "EXPLAIN SELECT 1"]
      expect(extractSqlFromArgs("psql", args)).toBe("EXPLAIN SELECT 1")
    })

    test("--command=value form", () => {
      const args = ["psql", "--command=EXPLAIN SELECT 1"]
      expect(extractSqlFromArgs("psql", args)).toBe("EXPLAIN SELECT 1")
    })

    test("no -c flag returns null", () => {
      const args = ["psql", "postgres://localhost:5433/db"]
      expect(extractSqlFromArgs("psql", args)).toBeNull()
    })

    test("complex connection string with -c", () => {
      const args = ["psql", "postgres://dc:dc@localhost:5433/dc", "-t", "-c", "SELECT DISTINCT id FROM search_index LIMIT 1"]
      expect(extractSqlFromArgs("psql", args)).toBe("SELECT DISTINCT id FROM search_index LIMIT 1")
    })

    test("bundled short flags -tAc", () => {
      const args = ["psql", "matter", "-tAc", "SELECT count(*) FROM argument_nodes"]
      expect(extractSqlFromArgs("psql", args)).toBe("SELECT count(*) FROM argument_nodes")
    })

    test("bundled with attached SQL -tAcSELECT", () => {
      const args = ["psql", "matter", "-tAcSELECT 1"]
      expect(extractSqlFromArgs("psql", args)).toBe("SELECT 1")
    })

    test("value-taking flag consumes next arg: -h host -tAc", () => {
      const args = ["psql", "-h", "localhost", "-tAc", "SELECT 1"]
      expect(extractSqlFromArgs("psql", args)).toBe("SELECT 1")
    })

    test("-Fc is a field separator, not a command flag", () => {
      // F takes a value; the attached "c" is that value, NOT -c
      const args = ["psql", "-Fc", "dbname"]
      expect(extractSqlFromArgs("psql", args)).toBeNull()
    })

    test("-F -c: the -c is F's separator value, not a command flag", () => {
      const args = ["psql", "-F", "-c", "dbname"]
      expect(extractSqlFromArgs("psql", args)).toBeNull()
    })

    test("unknown bundled letter aborts extraction (fail safe)", () => {
      const args = ["psql", "-tQc", "SELECT 1"]
      expect(extractSqlFromArgs("psql", args)).toBeNull()
    })

    test("multiple -c flags are ALL collected", () => {
      const args = ["psql", "-c", "SELECT 1", "-c", "DROP TABLE users"]
      expect(extractSqlFromArgs("psql", args)).toBe("SELECT 1;\nDROP TABLE users")
    })

    test("multiple -c: read-only pair still reads as read-only", () => {
      const args = ["psql", "-c", "SELECT 1", "-tAc", "SELECT 2"]
      const sql = extractSqlFromArgs("psql", args)
      expect(sql).toBe("SELECT 1;\nSELECT 2")
      expect(isSqlReadOnly(sql!)).toBe(true)
    })

    test("hidden write behind a leading SELECT is caught end-to-end", () => {
      const args = ["psql", "-c", "SELECT 1", "-c", "DROP TABLE users"]
      const sql = extractSqlFromArgs("psql", args)
      expect(isSqlReadOnly(sql!)).toBe(false)
    })
  })

  describe("mysql", () => {
    test("-e flag", () => {
      const args = ["mysql", "-u", "root", "-e", "SELECT * FROM users"]
      expect(extractSqlFromArgs("mysql", args)).toBe("SELECT * FROM users")
    })

    test("--execute flag", () => {
      const args = ["mysql", "mydb", "--execute", "SHOW TABLES"]
      expect(extractSqlFromArgs("mysql", args)).toBe("SHOW TABLES")
    })

    test("--execute=value form", () => {
      const args = ["mysql", "mydb", "--execute=SHOW TABLES"]
      expect(extractSqlFromArgs("mysql", args)).toBe("SHOW TABLES")
    })

    test("no -e flag returns null (interactive)", () => {
      const args = ["mysql", "-u", "root", "mydb"]
      expect(extractSqlFromArgs("mysql", args)).toBeNull()
    })
  })

  describe("sqlite3", () => {
    test("positional SQL after db path", () => {
      const args = ["sqlite3", "db.sqlite", "SELECT * FROM users"]
      expect(extractSqlFromArgs("sqlite3", args)).toBe("SELECT * FROM users")
    })

    test("with flags before db path", () => {
      const args = ["sqlite3", "-header", "-column", "db.sqlite", "SELECT count(*) FROM orders"]
      expect(extractSqlFromArgs("sqlite3", args)).toBe("SELECT count(*) FROM orders")
    })

    test("with -cmd flag (skips value)", () => {
      const args = ["sqlite3", "-cmd", ".headers on", "test.db", "SELECT 1"]
      expect(extractSqlFromArgs("sqlite3", args)).toBe("SELECT 1")
    })

    test("no SQL arg returns null (interactive)", () => {
      const args = ["sqlite3", "db.sqlite"]
      expect(extractSqlFromArgs("sqlite3", args)).toBeNull()
    })

    test("no args at all returns null", () => {
      const args = ["sqlite3"]
      expect(extractSqlFromArgs("sqlite3", args)).toBeNull()
    })
  })
})

describe("extractSqlFromPsql (deprecated, backward compat)", () => {
  test("double-quoted -c", () => {
    const cmd = `psql postgres://user:pass@localhost:5433/db -t -c "SELECT * FROM users" 2>&1`
    expect(extractSqlFromPsql(cmd)).toBe("SELECT * FROM users")
  })

  test("single-quoted -c", () => {
    const cmd = `psql -c 'SELECT count(*) FROM orders'`
    expect(extractSqlFromPsql(cmd)).toBe("SELECT count(*) FROM orders")
  })

  test("no -c flag returns null", () => {
    const cmd = `psql postgres://localhost:5433/db`
    expect(extractSqlFromPsql(cmd)).toBeNull()
  })
})

describe("isSqlReadOnly", () => {
  describe("read-only (should return true)", () => {
    const readOnly = [
      "SELECT 1",
      "SELECT * FROM users WHERE id = 1",
      "SELECT count(*) FROM orders",
      "SELECT DISTINCT advertiser_id FROM search_index LIMIT 1",
      "SELECT a.name, b.total FROM a JOIN b ON a.id = b.a_id",
      "WITH cte AS (SELECT * FROM t) SELECT * FROM cte",
      "SELECT * FROM users; SELECT * FROM orders",
      "SHOW search_path",
    ]

    for (const sql of readOnly) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(true)
      })
    }
  })

  describe("writes (should return false)", () => {
    const writes = [
      "INSERT INTO users VALUES (1, 'test')",
      "UPDATE users SET name = 'test' WHERE id = 1",
      "DELETE FROM users WHERE id = 1",
      "DROP TABLE users",
      "TRUNCATE users",
      "ALTER TABLE users ADD COLUMN email text",
      "CREATE TABLE t (id int)",
      // Mixed: one read + one write
      "SELECT 1; DROP TABLE users",
    ]

    for (const sql of writes) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(false)
      })
    }
  })

  describe("psql meta-commands (should return true)", () => {
    const safe = [
      "\\dt",
      "\\dt+",
      "\\dt api_keys",
      "\\dt+ api_keys",
      "\\d users",
      "\\d+ users",
      "\\di",
      "\\ds",
      "\\dv",
      "\\l",
      "\\dn",
      "\\df",
      "\\du",
      "\\conninfo",
      "\\encoding",
      "\\x",
      "\\pset format csv",
    ]

    for (const sql of safe) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(true)
      })
    }
  })

  describe("dangerous psql meta-commands (should return false)", () => {
    const dangerous = [
      "\\! rm -rf /",
      "\\copy users TO '/tmp/dump.csv'",
      "\\i /tmp/evil.sql",
      "\\o /tmp/output.txt",
    ]

    for (const sql of dangerous) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(false)
      })
    }
  })

  describe("SQLite dot-commands (should return true)", () => {
    const safe = [
      ".schema",
      ".schema known_devices",
      ".tables",
      ".databases",
      ".indexes",
      ".indices",
      ".fullschema",
      ".headers on",
      ".mode column",
      ".mode json",
      ".separator ,",
      ".show",
      ".dbinfo",
      ".stats",
      ".version",
      ".help",
      ".dump",
      ".dump users",
      ".timer on",
      ".width 20 10",
      ".explain on",
      ".eqp on",
    ]

    for (const sql of safe) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(true)
      })
    }
  })

  describe("dangerous SQLite dot-commands (should return false)", () => {
    const dangerous = [
      ".import data.csv users",
      ".restore main backup.db",
      ".open --new test.db",
      ".output /tmp/dump.txt",
      ".once /tmp/out.txt",
      ".save backup.db",
      ".backup main backup.db",
      ".read script.sql",
      ".system ls",
      ".shell echo hello",
    ]

    for (const sql of dangerous) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(false)
      })
    }
  })

  describe("SQLite PRAGMAs — read-only (should return true)", () => {
    const safe = [
      "PRAGMA table_info(users)",
      "PRAGMA table_info(device_event_attributions);",
      "PRAGMA table_xinfo(users)",
      "PRAGMA index_list(users)",
      "PRAGMA index_info(idx_users_email)",
      "PRAGMA foreign_key_list(orders)",
      "PRAGMA database_list",
      "PRAGMA compile_options",
      "PRAGMA integrity_check",
      "PRAGMA quick_check",
      "PRAGMA freelist_count",
      "PRAGMA page_count",
      "PRAGMA page_size",
      "PRAGMA journal_mode",
      "PRAGMA wal_checkpoint",
      "pragma table_info(users)",
    ]

    for (const sql of safe) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(true)
      })
    }
  })

  describe("SQLite PRAGMAs — setters (should return false)", () => {
    const setters = [
      "PRAGMA journal_mode = WAL",
      "PRAGMA foreign_keys = ON",
      "PRAGMA cache_size = 10000",
      "PRAGMA synchronous = OFF",
      "PRAGMA temp_store = MEMORY",
    ]

    for (const sql of setters) {
      test(sql, () => {
        expect(isSqlReadOnly(sql)).toBe(false)
      })
    }
  })

  test("unparseable SQL returns false", () => {
    expect(isSqlReadOnly("NOT VALID SQL !@#$")).toBe(false)
  })

  test("empty string returns true", () => {
    expect(isSqlReadOnly("")).toBe(true)
  })
})
