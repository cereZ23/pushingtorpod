"""Add EASM v2 models: projects, scopes, scan profiles, scan runs,
phase results, observations, issues, risk scores, alerts, relationships,
tickets, audit log, and extend assets/findings tables.

Revision ID: 006
Revises: 005
Create Date: 2026-02-25

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ==========================================================
    # 1. PROJECTS
    # ==========================================================
    op.create_table(
        'projects',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('seeds', sa.JSON(), nullable=True),
        sa.Column('settings', sa.JSON(), nullable=True),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['created_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_projects_tenant_id', 'projects', ['tenant_id'])
    op.create_index(
        'idx_projects_tenant_name_unique',
        'projects',
        ['tenant_id', 'name'],
        unique=True,
    )

    # ==========================================================
    # 2. SCOPES
    # ==========================================================
    op.create_table(
        'scopes',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('rule_type', sa.String(length=20), nullable=False),
        sa.Column('match_type', sa.String(length=20), nullable=False),
        sa.Column('pattern', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_scopes_project_id', 'scopes', ['project_id'])

    # ==========================================================
    # 3. SCAN PROFILES
    # ==========================================================
    op.create_table(
        'scan_profiles',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('scan_tier', sa.Integer(), server_default='1', nullable=True),
        sa.Column('port_scan_mode', sa.String(length=50), server_default='top-100', nullable=True),
        sa.Column('nuclei_tags', sa.JSON(), nullable=True),
        sa.Column('schedule_cron', sa.String(length=100), nullable=True),
        sa.Column('max_rate_pps', sa.Integer(), server_default='10', nullable=True),
        sa.Column('timeout_minutes', sa.Integer(), server_default='120', nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default='true', nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_scan_profiles_project_id', 'scan_profiles', ['project_id'])
    op.create_index(
        'idx_scan_profiles_project_enabled',
        'scan_profiles',
        ['project_id', 'enabled'],
    )

    # ==========================================================
    # 4. SCAN RUNS
    # ==========================================================
    op.create_table(
        'scan_runs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('profile_id', sa.Integer(), nullable=True),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=True),
        sa.Column('triggered_by', sa.String(length=100), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('stats', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('celery_task_id', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id']),
        sa.ForeignKeyConstraint(['profile_id'], ['scan_profiles.id']),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_scan_runs_project_id', 'scan_runs', ['project_id'])
    op.create_index('idx_scan_runs_tenant_id', 'scan_runs', ['tenant_id'])
    op.create_index('idx_scan_runs_status', 'scan_runs', ['status'])
    op.create_index(
        'idx_scan_runs_project_created',
        'scan_runs',
        ['project_id', 'created_at'],
    )

    # ==========================================================
    # 5. PHASE RESULTS
    # ==========================================================
    op.create_table(
        'phase_results',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_run_id', sa.Integer(), nullable=False),
        sa.Column('phase', sa.String(length=10), nullable=False),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('stats', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_phase_results_scan_run_id', 'phase_results', ['scan_run_id'])
    op.create_index(
        'idx_phase_results_run_phase_unique',
        'phase_results',
        ['scan_run_id', 'phase'],
        unique=True,
    )

    # ==========================================================
    # 6. OBSERVATIONS
    # ==========================================================
    op.create_table(
        'observations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('scan_run_id', sa.Integer(), nullable=True),
        sa.Column('asset_id', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('observation_type', sa.String(length=100), nullable=False),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id']),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_observations_tenant_id', 'observations', ['tenant_id'])
    op.create_index('idx_observations_scan_run_id', 'observations', ['scan_run_id'])
    op.create_index('idx_observations_type', 'observations', ['observation_type'])

    # ==========================================================
    # 7. ALERT POLICIES  (created before alerts due to FK)
    # ==========================================================
    op.create_table(
        'alert_policies',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('event_types', sa.JSON(), nullable=False),
        sa.Column('conditions', sa.JSON(), nullable=True),
        sa.Column('channels', sa.JSON(), nullable=False),
        sa.Column('cooldown_minutes', sa.Integer(), server_default='1440', nullable=True),
        sa.Column('digest_mode', sa.Boolean(), server_default='false', nullable=True),
        sa.Column('enabled', sa.Boolean(), server_default='true', nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_alert_policies_tenant_id', 'alert_policies', ['tenant_id'])
    op.create_index(
        'idx_alert_policies_tenant_enabled',
        'alert_policies',
        ['tenant_id', 'enabled'],
    )

    # ==========================================================
    # 8. ISSUES
    # ==========================================================
    op.create_table(
        'issues',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('project_id', sa.Integer(), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('root_cause', sa.String(length=255), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.Float(), server_default='1.0', nullable=True),
        sa.Column('status', sa.String(length=20), server_default='open', nullable=True),
        sa.Column('affected_assets_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('finding_count', sa.Integer(), server_default='0', nullable=True),
        sa.Column('risk_score', sa.Float(), server_default='0.0', nullable=True),
        sa.Column('assigned_to', sa.Integer(), nullable=True),
        sa.Column('ticket_ref', sa.String(length=255), nullable=True),
        sa.Column('sla_due_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id']),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id']),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_issues_tenant_id', 'issues', ['tenant_id'])
    op.create_index('idx_issues_project_id', 'issues', ['project_id'])
    op.create_index('idx_issues_status', 'issues', ['status'])
    op.create_index('idx_issues_severity', 'issues', ['severity'])
    op.create_index('idx_issues_sla_due_at', 'issues', ['sla_due_at'])
    op.create_index(
        'idx_issues_tenant_root_cause',
        'issues',
        ['tenant_id', 'root_cause'],
    )

    # ==========================================================
    # 9. ISSUE FINDINGS (junction table)
    # ==========================================================
    op.create_table(
        'issue_findings',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('issue_id', sa.Integer(), nullable=True),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['issue_id'], ['issues.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_issue_findings_issue_id', 'issue_findings', ['issue_id'])
    op.create_index('idx_issue_findings_finding_id', 'issue_findings', ['finding_id'])
    op.create_index(
        'idx_issue_findings_unique',
        'issue_findings',
        ['issue_id', 'finding_id'],
        unique=True,
    )

    # ==========================================================
    # 10. ISSUE ACTIVITIES
    # ==========================================================
    op.create_table(
        'issue_activities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('issue_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('old_value', sa.String(length=255), nullable=True),
        sa.Column('new_value', sa.String(length=255), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['issue_id'], ['issues.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_issue_activities_issue_id', 'issue_activities', ['issue_id'])
    op.create_index('idx_issue_activities_created_at', 'issue_activities', ['created_at'])

    # ==========================================================
    # 11. RISK SCORES
    # ==========================================================
    op.create_table(
        'risk_scores',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('scope_type', sa.String(length=20), nullable=False),
        sa.Column('scope_id', sa.Integer(), nullable=True),
        sa.Column('scan_run_id', sa.Integer(), nullable=True),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('grade', sa.String(length=2), nullable=True),
        sa.Column('components', sa.JSON(), nullable=True),
        sa.Column('explanation', sa.JSON(), nullable=True),
        sa.Column('previous_score', sa.Float(), nullable=True),
        sa.Column('delta', sa.Float(), nullable=True),
        sa.Column('scored_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_risk_scores_tenant_id', 'risk_scores', ['tenant_id'])
    op.create_index(
        'idx_risk_scores_scope',
        'risk_scores',
        ['scope_type', 'scope_id'],
    )
    op.create_index('idx_risk_scores_scan_run_id', 'risk_scores', ['scan_run_id'])
    op.create_index('idx_risk_scores_scored_at', 'risk_scores', ['scored_at'])

    # ==========================================================
    # 12. ALERTS
    # ==========================================================
    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('policy_id', sa.Integer(), nullable=True),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('related_asset_id', sa.Integer(), nullable=True),
        sa.Column('related_finding_id', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=20), server_default='pending', nullable=True),
        sa.Column('channels_sent', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('sent_at', sa.DateTime(), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['policy_id'], ['alert_policies.id']),
        sa.ForeignKeyConstraint(['related_asset_id'], ['assets.id']),
        sa.ForeignKeyConstraint(['related_finding_id'], ['findings.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_alerts_tenant_id', 'alerts', ['tenant_id'])
    op.create_index('idx_alerts_status', 'alerts', ['status'])
    op.create_index('idx_alerts_severity', 'alerts', ['severity'])
    op.create_index('idx_alerts_created_at', 'alerts', ['created_at'])
    op.create_index('idx_alerts_policy_id', 'alerts', ['policy_id'])

    # ==========================================================
    # 13. RELATIONSHIPS (asset graph edges)
    # ==========================================================
    op.create_table(
        'relationships',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('source_asset_id', sa.Integer(), nullable=True),
        sa.Column('target_asset_id', sa.Integer(), nullable=True),
        sa.Column('rel_type', sa.String(length=50), nullable=False),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(
            ['source_asset_id'], ['assets.id'], ondelete='CASCADE',
        ),
        sa.ForeignKeyConstraint(
            ['target_asset_id'], ['assets.id'], ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_relationships_tenant_id', 'relationships', ['tenant_id'])
    op.create_index('idx_relationships_source', 'relationships', ['source_asset_id'])
    op.create_index('idx_relationships_target', 'relationships', ['target_asset_id'])
    op.create_index('idx_relationships_rel_type', 'relationships', ['rel_type'])
    op.create_index(
        'idx_relationships_edge_unique',
        'relationships',
        ['source_asset_id', 'target_asset_id', 'rel_type'],
        unique=True,
    )

    # ==========================================================
    # 14. TICKETS (external ticket tracking)
    # ==========================================================
    op.create_table(
        'tickets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('issue_id', sa.Integer(), nullable=True),
        sa.Column('integration', sa.String(length=50), nullable=False),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('external_url', sa.String(length=2048), nullable=True),
        sa.Column('external_status', sa.String(length=100), nullable=True),
        sa.Column('sync_status', sa.String(length=50), server_default='synced', nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['issue_id'], ['issues.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_tickets_tenant_id', 'tickets', ['tenant_id'])
    op.create_index('idx_tickets_issue_id', 'tickets', ['issue_id'])
    op.create_index(
        'idx_tickets_integration_external',
        'tickets',
        ['integration', 'external_id'],
    )

    # ==========================================================
    # 15. AUDIT LOG
    # ==========================================================
    op.create_table(
        'audit_log',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('tenant_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('entity_type', sa.String(length=50), nullable=True),
        sa.Column('entity_id', sa.Integer(), nullable=True),
        sa.Column('old_value', sa.JSON(), nullable=True),
        sa.Column('new_value', sa.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('idx_audit_log_tenant_id', 'audit_log', ['tenant_id'])
    op.create_index('idx_audit_log_user_id', 'audit_log', ['user_id'])
    op.create_index(
        'idx_audit_log_entity',
        'audit_log',
        ['entity_type', 'entity_id'],
    )
    op.create_index('idx_audit_log_created_at', 'audit_log', ['created_at'])
    op.create_index('idx_audit_log_action', 'audit_log', ['action'])

    # ==========================================================
    # 16. COLUMN ADDITIONS: assets
    # ==========================================================
    op.add_column('assets', sa.Column('project_id', sa.Integer(), nullable=True))
    op.add_column('assets', sa.Column('asset_key', sa.String(length=255), nullable=True))
    op.add_column('assets', sa.Column('status', sa.String(length=20), server_default='active', nullable=True))
    op.add_column('assets', sa.Column('dns_records', sa.JSON(), nullable=True))
    op.add_column('assets', sa.Column('http_metadata', sa.JSON(), nullable=True))
    op.add_column('assets', sa.Column('technologies', sa.JSON(), nullable=True))
    op.add_column('assets', sa.Column('cloud_provider', sa.String(length=100), nullable=True))
    op.add_column('assets', sa.Column('cdn_provider', sa.String(length=100), nullable=True))
    op.add_column('assets', sa.Column('is_cdn_fronted', sa.Boolean(), server_default='false', nullable=True))
    op.add_column('assets', sa.Column('criticality', sa.String(length=20), server_default='standard', nullable=True))
    op.add_column('assets', sa.Column('owner', sa.String(length=255), nullable=True))
    op.create_foreign_key(
        'fk_assets_project_id',
        'assets',
        'projects',
        ['project_id'],
        ['id'],
    )

    # ==========================================================
    # 17. COLUMN ADDITIONS: findings
    # ==========================================================
    op.add_column('findings', sa.Column('finding_key', sa.String(length=500), nullable=True))
    op.add_column('findings', sa.Column('finding_type', sa.String(length=50), nullable=True))
    op.add_column('findings', sa.Column('control_id', sa.String(length=50), nullable=True))
    op.add_column('findings', sa.Column('confidence', sa.Float(), server_default='1.0', nullable=True))
    op.add_column('findings', sa.Column('remediation', sa.Text(), nullable=True))
    op.add_column('findings', sa.Column('first_seen_run', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('last_seen_run', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('resolved_at', sa.DateTime(), nullable=True))
    op.add_column('findings', sa.Column('resolved_by', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('epss_score', sa.Float(), nullable=True))
    op.add_column('findings', sa.Column('is_kev', sa.Boolean(), server_default='false', nullable=True))
    op.add_column('findings', sa.Column('retest_scan_run_id', sa.Integer(), nullable=True))
    op.add_column('findings', sa.Column('retest_result', sa.String(length=20), nullable=True))
    op.add_column('findings', sa.Column('retest_count', sa.Integer(), server_default='0', nullable=True))
    op.add_column('findings', sa.Column('needs_review', sa.Boolean(), server_default='false', nullable=True))
    op.create_foreign_key(
        'fk_findings_first_seen_run',
        'findings',
        'scan_runs',
        ['first_seen_run'],
        ['id'],
    )
    op.create_foreign_key(
        'fk_findings_last_seen_run',
        'findings',
        'scan_runs',
        ['last_seen_run'],
        ['id'],
    )
    op.create_foreign_key(
        'fk_findings_resolved_by',
        'findings',
        'users',
        ['resolved_by'],
        ['id'],
    )
    op.create_foreign_key(
        'fk_findings_retest_scan_run_id',
        'findings',
        'scan_runs',
        ['retest_scan_run_id'],
        ['id'],
    )


def downgrade() -> None:
    # ==========================================================
    # Drop FK constraints and columns from findings
    # ==========================================================
    op.drop_constraint('fk_findings_retest_scan_run_id', 'findings', type_='foreignkey')
    op.drop_constraint('fk_findings_resolved_by', 'findings', type_='foreignkey')
    op.drop_constraint('fk_findings_last_seen_run', 'findings', type_='foreignkey')
    op.drop_constraint('fk_findings_first_seen_run', 'findings', type_='foreignkey')

    op.drop_column('findings', 'needs_review')
    op.drop_column('findings', 'retest_count')
    op.drop_column('findings', 'retest_result')
    op.drop_column('findings', 'retest_scan_run_id')
    op.drop_column('findings', 'is_kev')
    op.drop_column('findings', 'epss_score')
    op.drop_column('findings', 'resolved_by')
    op.drop_column('findings', 'resolved_at')
    op.drop_column('findings', 'last_seen_run')
    op.drop_column('findings', 'first_seen_run')
    op.drop_column('findings', 'remediation')
    op.drop_column('findings', 'confidence')
    op.drop_column('findings', 'control_id')
    op.drop_column('findings', 'finding_type')
    op.drop_column('findings', 'finding_key')

    # ==========================================================
    # Drop FK constraint and columns from assets
    # ==========================================================
    op.drop_constraint('fk_assets_project_id', 'assets', type_='foreignkey')

    op.drop_column('assets', 'owner')
    op.drop_column('assets', 'criticality')
    op.drop_column('assets', 'is_cdn_fronted')
    op.drop_column('assets', 'cdn_provider')
    op.drop_column('assets', 'cloud_provider')
    op.drop_column('assets', 'technologies')
    op.drop_column('assets', 'http_metadata')
    op.drop_column('assets', 'dns_records')
    op.drop_column('assets', 'status')
    op.drop_column('assets', 'asset_key')
    op.drop_column('assets', 'project_id')

    # ==========================================================
    # Drop tables in reverse dependency order
    # ==========================================================

    # audit_log
    op.drop_index('idx_audit_log_action', table_name='audit_log')
    op.drop_index('idx_audit_log_created_at', table_name='audit_log')
    op.drop_index('idx_audit_log_entity', table_name='audit_log')
    op.drop_index('idx_audit_log_user_id', table_name='audit_log')
    op.drop_index('idx_audit_log_tenant_id', table_name='audit_log')
    op.drop_table('audit_log')

    # tickets
    op.drop_index('idx_tickets_integration_external', table_name='tickets')
    op.drop_index('idx_tickets_issue_id', table_name='tickets')
    op.drop_index('idx_tickets_tenant_id', table_name='tickets')
    op.drop_table('tickets')

    # relationships
    op.drop_index('idx_relationships_edge_unique', table_name='relationships')
    op.drop_index('idx_relationships_rel_type', table_name='relationships')
    op.drop_index('idx_relationships_target', table_name='relationships')
    op.drop_index('idx_relationships_source', table_name='relationships')
    op.drop_index('idx_relationships_tenant_id', table_name='relationships')
    op.drop_table('relationships')

    # alerts
    op.drop_index('idx_alerts_policy_id', table_name='alerts')
    op.drop_index('idx_alerts_created_at', table_name='alerts')
    op.drop_index('idx_alerts_severity', table_name='alerts')
    op.drop_index('idx_alerts_status', table_name='alerts')
    op.drop_index('idx_alerts_tenant_id', table_name='alerts')
    op.drop_table('alerts')

    # risk_scores
    op.drop_index('idx_risk_scores_scored_at', table_name='risk_scores')
    op.drop_index('idx_risk_scores_scan_run_id', table_name='risk_scores')
    op.drop_index('idx_risk_scores_scope', table_name='risk_scores')
    op.drop_index('idx_risk_scores_tenant_id', table_name='risk_scores')
    op.drop_table('risk_scores')

    # issue_activities
    op.drop_index('idx_issue_activities_created_at', table_name='issue_activities')
    op.drop_index('idx_issue_activities_issue_id', table_name='issue_activities')
    op.drop_table('issue_activities')

    # issue_findings
    op.drop_index('idx_issue_findings_unique', table_name='issue_findings')
    op.drop_index('idx_issue_findings_finding_id', table_name='issue_findings')
    op.drop_index('idx_issue_findings_issue_id', table_name='issue_findings')
    op.drop_table('issue_findings')

    # issues
    op.drop_index('idx_issues_tenant_root_cause', table_name='issues')
    op.drop_index('idx_issues_sla_due_at', table_name='issues')
    op.drop_index('idx_issues_severity', table_name='issues')
    op.drop_index('idx_issues_status', table_name='issues')
    op.drop_index('idx_issues_project_id', table_name='issues')
    op.drop_index('idx_issues_tenant_id', table_name='issues')
    op.drop_table('issues')

    # alert_policies
    op.drop_index('idx_alert_policies_tenant_enabled', table_name='alert_policies')
    op.drop_index('idx_alert_policies_tenant_id', table_name='alert_policies')
    op.drop_table('alert_policies')

    # observations
    op.drop_index('idx_observations_type', table_name='observations')
    op.drop_index('idx_observations_scan_run_id', table_name='observations')
    op.drop_index('idx_observations_tenant_id', table_name='observations')
    op.drop_table('observations')

    # phase_results
    op.drop_index('idx_phase_results_run_phase_unique', table_name='phase_results')
    op.drop_index('idx_phase_results_scan_run_id', table_name='phase_results')
    op.drop_table('phase_results')

    # scan_runs
    op.drop_index('idx_scan_runs_project_created', table_name='scan_runs')
    op.drop_index('idx_scan_runs_status', table_name='scan_runs')
    op.drop_index('idx_scan_runs_tenant_id', table_name='scan_runs')
    op.drop_index('idx_scan_runs_project_id', table_name='scan_runs')
    op.drop_table('scan_runs')

    # scan_profiles
    op.drop_index('idx_scan_profiles_project_enabled', table_name='scan_profiles')
    op.drop_index('idx_scan_profiles_project_id', table_name='scan_profiles')
    op.drop_table('scan_profiles')

    # scopes
    op.drop_index('idx_scopes_project_id', table_name='scopes')
    op.drop_table('scopes')

    # projects
    op.drop_index('idx_projects_tenant_name_unique', table_name='projects')
    op.drop_index('idx_projects_tenant_id', table_name='projects')
    op.drop_table('projects')
