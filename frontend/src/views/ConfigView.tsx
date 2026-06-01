import { useEffect, useMemo, useState } from 'react';
import TechButton from '../components/common/TechButton';
import TechPanel from '../components/common/TechPanel';
import { api } from '../lib/api';
import { API_BASE_URL } from '../lib/config';
import type { AdminGlobalConfigResponse } from '../lib/types';

interface ConfigDraft {
  scanDirs: string;
  watchDirs: string;
  includeExtensions: string;
  excludePaths: string;
  heartbeatIntervalSec: string;
  maxFileSizeMb: string;
  upgradeJson: string;
}

function parseLines(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function buildDraft(config?: AdminGlobalConfigResponse | null): ConfigDraft {
  const source = config?.config || {};
  return {
    scanDirs: Array.isArray(source.scan_dirs) ? source.scan_dirs.join('\n') : '',
    watchDirs: Array.isArray(source.watch_dirs) ? source.watch_dirs.join('\n') : '',
    includeExtensions: Array.isArray(source.include_extensions) ? source.include_extensions.join('\n') : '',
    excludePaths: Array.isArray(source.exclude_paths) ? source.exclude_paths.join('\n') : '',
    heartbeatIntervalSec: String(source.heartbeat_interval_sec || ''),
    maxFileSizeMb: String(source.max_file_size_mb || ''),
    upgradeJson: JSON.stringify(source.upgrade || {}, null, 2),
  };
}

function hasInvalidWindowsPathChars(value: string) {
  const safe = value.replace(/%[A-Za-z_][A-Za-z0-9_]*%/g, 'ENVVAR');
  const withoutDrive = /^[A-Za-z]:[\\/]/.test(safe) ? safe.slice(2) : safe;
  return withoutDrive
    .split(/[\\/]+/)
    .filter(Boolean)
    .some((part) => /[<>:"|?*]/.test(part));
}

function validatePathLines(label: string, value: string) {
  for (const item of parseLines(value)) {
    if (hasInvalidWindowsPathChars(item)) {
      throw new Error(`${label} contains invalid Windows path characters: ${item}`);
    }
  }
}

function FieldLabel(props: { children: string }) {
  return <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-[#8fb9d6]">{props.children}</div>;
}

function TextAreaField(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  rows?: number;
}) {
  return (
    <label className="block">
      <FieldLabel>{props.label}</FieldLabel>
      <textarea
        value={props.value}
        rows={props.rows || 5}
        onChange={(event) => props.onChange(event.target.value)}
        className="w-full rounded border border-[rgba(0,240,255,0.18)] bg-[rgba(5,10,21,0.72)] px-3 py-2 text-sm text-white outline-none focus:border-[#00f0ff]"
      />
    </label>
  );
}

function NumberField(props: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="block">
      <FieldLabel>{props.label}</FieldLabel>
      <input
        value={props.value}
        onChange={(event) => props.onChange(event.target.value)}
        className="w-full rounded border border-[rgba(0,240,255,0.18)] bg-[rgba(5,10,21,0.72)] px-3 py-2 text-sm text-white outline-none focus:border-[#00f0ff]"
      />
    </label>
  );
}

export default function ConfigView() {
  const [adminToken, setAdminToken] = useState(() => window.localStorage.getItem('safeguard_admin_token') || '');
  const [config, setConfig] = useState<AdminGlobalConfigResponse | null>(null);
  const [draft, setDraft] = useState<ConfigDraft>(() => buildDraft(null));
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [errorText, setErrorText] = useState('');
  const [successText, setSuccessText] = useState('');
  const authorized = Boolean(config);

  const versionText = useMemo(() => (config ? `v${config.config_version}` : '-'), [config]);

  useEffect(() => {
    if (!adminToken.trim()) return;
    void loadConfig(adminToken.trim(), false);
  }, []);

  async function loadConfig(token = adminToken.trim(), showSuccess = true) {
    if (!token) {
      setErrorText('Admin token is required.');
      setSuccessText('');
      setConfig(null);
      return;
    }
    setLoading(true);
    setErrorText('');
    setSuccessText('');
    try {
      const response = await api.getAdminConfigs(API_BASE_URL, token);
      window.localStorage.setItem('safeguard_admin_token', token);
      setConfig(response);
      setDraft(buildDraft(response));
      if (showSuccess) setSuccessText('Admin token verified.');
    } catch (error) {
      setConfig(null);
      setErrorText(error instanceof Error ? error.message : 'Config load failed.');
    } finally {
      setLoading(false);
    }
  }

  async function saveConfig() {
    if (!adminToken.trim()) {
      setErrorText('Admin token is required.');
      setSuccessText('');
      return;
    }
    setSaving(true);
    setErrorText('');
    setSuccessText('');
    try {
      validatePathLines('scan_dirs', draft.scanDirs);
      validatePathLines('watch_dirs', draft.watchDirs);
      validatePathLines('exclude_paths', draft.excludePaths);
      const upgrade = JSON.parse(draft.upgradeJson || '{}');
      const response = await api.updateAdminConfigs(API_BASE_URL, adminToken.trim(), {
        scan_dirs: parseLines(draft.scanDirs),
        watch_dirs: parseLines(draft.watchDirs),
        include_extensions: parseLines(draft.includeExtensions),
        exclude_paths: parseLines(draft.excludePaths),
        heartbeat_interval_sec: Number(draft.heartbeatIntervalSec || 0) || undefined,
        max_file_size_mb: Number(draft.maxFileSizeMb || 0) || undefined,
        upgrade,
      });
      const nextConfig = { config_version: response.config_version, config: response.config, agent_overrides: config?.agent_overrides || [] };
      setConfig(nextConfig);
      setDraft(buildDraft(nextConfig));
      setSuccessText(`Config saved as v${response.config_version}.`);
    } catch (error) {
      setErrorText(error instanceof Error ? error.message : 'Config save failed.');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="grid gap-4">
      <TechPanel title="System Config" bodyClassName="p-5">
        <div className="grid gap-4">
          <div className="grid gap-3 lg:grid-cols-[1fr_auto_auto]">
            <input
              type="password"
              value={adminToken}
              onChange={(event) => setAdminToken(event.target.value)}
              className="rounded border border-[rgba(0,240,255,0.18)] bg-[rgba(5,10,21,0.72)] px-3 py-2 text-sm text-white outline-none focus:border-[#00f0ff]"
              placeholder="SAFEGUARD_ADMIN_TOKEN"
            />
            <TechButton onClick={() => void loadConfig()} disabled={loading}>
              {loading ? 'Verifying...' : 'Verify'}
            </TechButton>
            <div className={`rounded border px-4 py-2 text-sm ${authorized ? 'border-[#1abc9c] text-[#1abc9c]' : 'border-[#ffb020] text-[#ffb020]'}`}>
              {authorized ? 'Authorized' : 'Not verified'} / {versionText}
            </div>
          </div>

          {errorText ? <div className="rounded border border-[#ff4d4f] bg-[rgba(255,77,79,0.12)] px-4 py-3 text-sm text-[#ffb4b4]">{errorText}</div> : null}
          {successText ? <div className="rounded border border-[#1abc9c] bg-[rgba(26,188,156,0.12)] px-4 py-3 text-sm text-[#8df5d7]">{successText}</div> : null}

          <div className="grid gap-4 xl:grid-cols-2">
            <div className="grid gap-4">
              <TextAreaField label="scan_dirs" value={draft.scanDirs} onChange={(value) => setDraft((prev) => ({ ...prev, scanDirs: value }))} />
              <TextAreaField label="watch_dirs" value={draft.watchDirs} onChange={(value) => setDraft((prev) => ({ ...prev, watchDirs: value }))} />
              <TextAreaField label="include_extensions" value={draft.includeExtensions} onChange={(value) => setDraft((prev) => ({ ...prev, includeExtensions: value }))} rows={4} />
              <TextAreaField label="exclude_paths" value={draft.excludePaths} onChange={(value) => setDraft((prev) => ({ ...prev, excludePaths: value }))} />
            </div>
            <div className="grid content-start gap-4">
              <div className="grid gap-4 md:grid-cols-2">
                <NumberField label="heartbeat_interval_sec" value={draft.heartbeatIntervalSec} onChange={(value) => setDraft((prev) => ({ ...prev, heartbeatIntervalSec: value }))} />
                <NumberField label="max_file_size_mb" value={draft.maxFileSizeMb} onChange={(value) => setDraft((prev) => ({ ...prev, maxFileSizeMb: value }))} />
              </div>
              <TextAreaField label="upgrade" value={draft.upgradeJson} onChange={(value) => setDraft((prev) => ({ ...prev, upgradeJson: value }))} rows={12} />
              <div className="flex justify-end">
                <TechButton onClick={() => void saveConfig()} disabled={saving || loading}>
                  {saving ? 'Saving...' : 'Save Config'}
                </TechButton>
              </div>
            </div>
          </div>
        </div>
      </TechPanel>
    </div>
  );
}
