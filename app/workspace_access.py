"""Keep migration permissions attached to immutable configuration versions."""

READ_ROLES = {"owner", "editor", "reviewer", "viewer"}
WRITE_ROLES = {"owner", "editor"}


def initialize_workspace_access(conn):
    project_columns = {row[1] for row in conn.execute("PRAGMA table_info(migration_projects)")}
    if "access_identity" not in project_columns:
        conn.execute("ALTER TABLE migration_projects ADD COLUMN access_identity TEXT NOT NULL DEFAULT ''")
    conn.execute("UPDATE migration_projects SET access_identity=lower(hex(randomblob(16))) WHERE access_identity=''")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS migration_project_access_identity
        AFTER INSERT ON migration_projects WHEN NEW.access_identity=''
        BEGIN
          UPDATE migration_projects SET access_identity=lower(hex(randomblob(16))) WHERE id=NEW.id;
        END""")
    # Deliberately retain project IDs after project removal: old configurations
    # must not silently become shared when their project has been deleted.
    conn.execute("""CREATE TABLE IF NOT EXISTS config_workspace_projects (
        workspace_id INTEGER NOT NULL, project_id INTEGER NOT NULL,
        project_identity TEXT NOT NULL DEFAULT '',
        PRIMARY KEY(workspace_id, project_id),
        FOREIGN KEY(workspace_id) REFERENCES config_workspaces(id) ON DELETE CASCADE
    )""")
    access_columns = {row[1] for row in conn.execute("PRAGMA table_info(config_workspace_projects)")}
    if "project_identity" not in access_columns:
        conn.execute("ALTER TABLE config_workspace_projects ADD COLUMN project_identity TEXT NOT NULL DEFAULT ''")
        conn.execute("""UPDATE config_workspace_projects SET project_identity=COALESCE(
            (SELECT access_identity FROM migration_projects WHERE id=project_id), '')""")
    conn.execute("CREATE INDEX IF NOT EXISTS config_workspace_lineage ON config_workspaces(profile_id,original_name)")
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT p.base_workspace_id,p.id,p.access_identity FROM migration_projects p
        JOIN config_workspaces w ON w.id=p.base_workspace_id""")
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT s.staging_workspace_id,s.project_id,p.access_identity FROM migration_sources s
        JOIN config_workspaces w ON w.id=s.staging_workspace_id
        JOIN migration_projects p ON p.id=s.project_id""")
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT o.workspace_id,o.project_id,p.access_identity FROM migration_outputs o
        JOIN config_workspaces w ON w.id=o.workspace_id
        JOIN migration_projects p ON p.id=o.project_id""")
    # Older releases did not record parent IDs, but kept original_name/profile
    # across immutable versions. Restrict these older versions as well. Multiple
    # matching projects are conservative: access is required to every one.
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT older.id,acl.project_id,acl.project_identity FROM config_workspaces older
        JOIN config_workspaces linked
          ON linked.profile_id=older.profile_id
         AND linked.original_name=older.original_name
        JOIN config_workspace_projects acl ON acl.workspace_id=linked.id
        WHERE older.source='edit' OR older.source LIKE 'migration-%'""")


def link_workspace_project(conn, workspace_id, project_id):
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT ?,id,access_identity FROM migration_projects WHERE id=?""", (workspace_id, project_id))


def inherit_workspace_access(conn, previous_id, new_id):
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT ?,project_id,project_identity FROM config_workspace_projects WHERE workspace_id=?""",
                 (new_id, previous_id))
    # Also capture current links before their IDs advance to the new version.
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT ?,id,access_identity FROM migration_projects WHERE base_workspace_id=?
        UNION SELECT ?,s.project_id,p.access_identity FROM migration_sources s
          JOIN migration_projects p ON p.id=s.project_id WHERE s.staging_workspace_id=?
        UNION SELECT ?,o.project_id,p.access_identity FROM migration_outputs o
          JOIN migration_projects p ON p.id=o.project_id WHERE o.workspace_id=?""",
                 (previous_id, previous_id, previous_id, previous_id, previous_id, previous_id))
    conn.execute("""INSERT OR IGNORE INTO config_workspace_projects
        SELECT ?,project_id,project_identity FROM config_workspace_projects WHERE workspace_id=?""",
                 (new_id, previous_id))


def workspace_allowed(conn, workspace_id, username, write=False):
    workspace = conn.execute("SELECT source FROM config_workspaces WHERE id=?",
                             (workspace_id,)).fetchone()
    if workspace is None or not username:
        return False
    project_grants = {(int(row[0]), str(row[1])) for row in conn.execute("""
        SELECT project_id,project_identity FROM config_workspace_projects WHERE workspace_id=?
        UNION SELECT id,access_identity FROM migration_projects WHERE base_workspace_id=?
        UNION SELECT s.project_id,p.access_identity FROM migration_sources s
          JOIN migration_projects p ON p.id=s.project_id WHERE s.staging_workspace_id=?
        UNION SELECT o.project_id,p.access_identity FROM migration_outputs o
          JOIN migration_projects p ON p.id=o.project_id WHERE o.workspace_id=?
        """, (workspace_id, workspace_id, workspace_id, workspace_id))}
    if not project_grants:
        # Normal policy-builder workspaces remain shared as before. Orphaned
        # migration snapshots fail closed instead of leaking customer configs.
        return not str(workspace["source"]).startswith("migration-")
    permitted = WRITE_ROLES if write else READ_ROLES
    for project_id, identity in project_grants:
        project = conn.execute("SELECT owner,access_identity FROM migration_projects WHERE id=?",
                               (project_id,)).fetchone()
        # SQLite may reuse a deleted integer primary key. A new project with the
        # same numeric ID must never inherit the old project's configuration.
        if project is None or not identity or project["access_identity"] != identity:
            return False
        if username == str(project["owner"] or "admin"):
            continue
        role = conn.execute("""SELECT role FROM migration_project_roles
            WHERE project_id=? AND username=?""", (project_id, username)).fetchone()
        if role is None or role["role"] not in permitted:
            return False
    return True
