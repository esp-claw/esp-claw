import { createSignal, For, onMount, Show, type Component } from 'solid-js';
import { Key } from '@solid-primitives/keyed';
import { t, tf } from '../i18n';
import {
  fetchWasmAppSettings,
  fetchWasmApps,
  setWasmAppEnabled,
  setWasmAppSetting,
  type AppConfig,
  type WasmApp,
  type WasmAppSetting,
} from '../api/client';
import { createConfigTab } from '../state/configTab';
import { pushToast } from '../state/toast';
import { TabShell } from '../components/layout/TabShell';
import { PageHeader } from '../components/ui/PageHeader';
import { CollapsibleConfigBlock, StaticConfigBlock } from '../components/ui/ConfigBlocks';
import { SelectInput, TextArea, TextInput } from '../components/ui/FormField';
import { SavePanel } from '../components/ui/SavePanel';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Switch } from '../components/ui/Switch';
import { RestartConfirmModal } from '../components/system/RestartConfirmModal';

const TIME_OF_DAY = /^([01]\d|2[0-3]):[0-5]\d$/;

type TrustForm = {
  trusted_keys: string;
  allow_unsigned: string;
  update_check_time: string;
};

/** app_trusted_keys is a JSON array; the form edits one key per line. */
function keysToLines(raw: string | undefined): string {
  try {
    const parsed = JSON.parse(raw ?? '');
    if (Array.isArray(parsed)) return parsed.filter((k) => typeof k === 'string').join('\n');
  } catch {
    /* empty or not JSON: show as is */
  }
  return raw ?? '';
}

function linesToKeys(lines: string): string {
  const keys = lines
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);
  return keys.length ? JSON.stringify(keys) : '';
}

const errorMessage = (err: unknown) => (err as Error).message || (t('saveError') as string);

const SettingRow: Component<{
  app: string;
  setting: WasmAppSetting;
  onChanged: () => void;
}> = (props) => {
  const initial = () => (props.setting.secret ? '' : (props.setting.value ?? ''));
  const [draft, setDraft] = createSignal(initial());
  const [busy, setBusy] = createSignal(false);

  const run = async (value: string | null) => {
    setBusy(true);
    try {
      const result = await setWasmAppSetting(props.app, props.setting.key, value);
      pushToast(result.message || (t('saveSuccess') as string), 'success');
      props.onChanged();
    } catch (err) {
      pushToast(errorMessage(err), 'error', 5000);
    } finally {
      setBusy(false);
    }
  };

  const status = () => {
    const s = props.setting;
    if (s.secret) return t(s.set ? 'wasmSecretSet' : 'wasmSecretUnset') as string;
    if (!s.set) return t('wasmSettingUnset') as string;
    return s.default ? (t('wasmSettingDefault') as string) : '';
  };
  const label = () => `${props.setting.key} (${props.setting.type})`;
  const hint = () => [props.setting.description, status()].filter(Boolean).join(' · ');
  const canSave = () => !busy() && draft() !== '' && draft() !== initial();

  return (
    <div class="flex flex-col gap-2 sm:flex-row sm:items-end">
      <div class="flex-1 min-w-0">
        <Show
          when={props.setting.type === 'bool' && !props.setting.secret}
          fallback={
            <TextInput
              label={label()}
              hint={hint()}
              type={
                props.setting.secret ? 'password' : props.setting.type === 'int' ? 'number' : 'text'
              }
              autocomplete={props.setting.secret ? 'new-password' : 'off'}
              value={draft()}
              onInput={(event) => setDraft(event.currentTarget.value)}
            />
          }
        >
          <SelectInput
            label={label()}
            hint={hint()}
            value={draft()}
            onChange={(event) => setDraft(event.currentTarget.value)}
          >
            <option value="" disabled>
              {t('wasmSettingUnset') as string}
            </option>
            <option value="true">true</option>
            <option value="false">false</option>
          </SelectInput>
        </Show>
      </div>
      <div class="flex gap-2 sm:pb-6">
        <Button size="sm" variant="primary" disabled={!canSave()} onClick={() => run(draft())}>
          {t('wasmSettingSave')}
        </Button>
        <Button
          size="sm"
          variant="secondary"
          disabled={busy() || !props.setting.set}
          onClick={() => run(null)}
        >
          {t('wasmSettingReset')}
        </Button>
      </div>
    </div>
  );
};

const AppRow: Component<{ app: WasmApp; onChanged: () => void }> = (props) => {
  const [settings, setSettings] = createSignal<WasmAppSetting[] | null>(null);
  const [settingsError, setSettingsError] = createSignal<string | null>(null);
  const [busy, setBusy] = createSignal(false);

  const loadSettings = async () => {
    setSettingsError(null);
    try {
      setSettings(await fetchWasmAppSettings(props.app.name));
    } catch (err) {
      setSettingsError(errorMessage(err));
    }
  };

  const toggle = async (enabled: boolean) => {
    setBusy(true);
    try {
      const result = await setWasmAppEnabled(props.app.name, enabled);
      pushToast(result.message || (t('saveSuccess') as string), 'success');
    } catch (err) {
      pushToast(errorMessage(err), 'error', 5000);
    } finally {
      setBusy(false);
      props.onChanged();
    }
  };

  const timerText = () => {
    const timer = props.app.timer;
    if (!timer) return '';
    const base = tf('wasmTimerInfo', {
      interval: timer.interval_s,
      state: timer.state,
      runs: timer.runs,
    });
    const next =
      timer.next_in_s !== undefined ? tf('wasmTimerNext', { next: timer.next_in_s }) : '';
    return [base, next, timer.last_error].filter(Boolean).join(', ');
  };

  return (
    <CollapsibleConfigBlock
      title={`${props.app.name} ${props.app.version}`}
      defaultOpen={false}
      onOpenChange={(open) => {
        if (open && settings() === null) void loadSettings();
      }}
      headerEnd={
        <>
          <span class="text-[0.75rem] text-[var(--color-text-muted)]">{props.app.state}</span>
          <Switch
            checked={props.app.enabled}
            disabled={busy()}
            onChange={(checked) => void toggle(checked)}
            label={t('wasmEnabled') as string}
          />
        </>
      }
    >
      <div class="flex flex-col gap-3 pt-2 text-[0.82rem] text-[var(--color-text-secondary)]">
        <Show when={props.app.description}>
          <p class="m-0">{props.app.description}</p>
        </Show>
        <p class="m-0 text-[var(--color-text-muted)]">
          {[
            props.app.key_id ? tf('wasmKey', { key: props.app.key_id }) : t('wasmUnsigned'),
            tf('wasmCalls', { calls: props.app.calls }),
          ].join(' · ')}
        </p>
        <Show when={props.app.tools.length > 0}>
          <p class="m-0">
            {t('wasmTools')}:{' '}
            <span class="font-mono text-[var(--color-text-primary)]">
              {props.app.tools.join(', ')}
            </span>
          </p>
        </Show>
        <Show when={props.app.timer}>
          <p class="m-0">
            {t('wasmTimer')}: {timerText()}
          </p>
        </Show>
        <Show when={props.app.last_error}>
          <Banner kind="error" message={`${t('wasmLastError')}: ${props.app.last_error}`} />
        </Show>
        <div class="flex flex-col gap-3 pt-1">
          <span class="text-[0.85rem] font-semibold text-[var(--color-text-primary)]">
            {t('wasmSettings')}
          </span>
          <Show when={settingsError()}>
            <Banner kind="error" message={settingsError() ?? undefined} />
          </Show>
          <Show when={settings()}>
            {(list) => (
              <Show when={list().length > 0} fallback={<p class="m-0">{t('wasmNoSettings')}</p>}>
                <For each={list()}>
                  {(setting) => (
                    <SettingRow app={props.app.name} setting={setting} onChanged={loadSettings} />
                  )}
                </For>
              </Show>
            )}
          </Show>
        </div>
      </div>
    </CollapsibleConfigBlock>
  );
};

export const WasmAppsPage: Component<{ onRestartRequest: () => void }> = (props) => {
  const tab = createConfigTab<TrustForm>({
    tab: 'wasm',
    groups: ['capabilities'],
    toForm: (config: Partial<AppConfig>) => ({
      trusted_keys: keysToLines(config.app_trusted_keys),
      allow_unsigned: config.app_allow_unsigned === 'true' ? 'true' : 'false',
      update_check_time: config.update_check_time ?? '',
    }),
    fromForm: (form) => ({
      app_trusted_keys: linesToKeys(form.trusted_keys),
      app_allow_unsigned: form.allow_unsigned,
      update_check_time: form.update_check_time.trim(),
    }),
  });
  const [confirmOpen, setConfirmOpen] = createSignal(false);
  /* undefined: loading, null: not compiled into this firmware */
  const [apps, setApps] = createSignal<WasmApp[] | null | undefined>(undefined);
  const [appsError, setAppsError] = createSignal<string | null>(null);

  const loadApps = async () => {
    setAppsError(null);
    try {
      setApps(await fetchWasmApps());
    } catch (err) {
      setApps([]);
      setAppsError(errorMessage(err));
    }
  };

  onMount(() => void loadApps());

  const timeInvalid = () => {
    const value = tab.form.update_check_time.trim();
    return value !== '' && !TIME_OF_DAY.test(value);
  };

  const handleSave = async () => {
    if (timeInvalid()) {
      pushToast(t('wasmUpdateCheckInvalid') as string, 'error', 5000);
      return;
    }
    await tab.save();
    setConfirmOpen(true);
  };

  return (
    <TabShell>
      <PageHeader title={t('navWasmApps') as string} description={t('wasmDesc') as string} />
      <Show
        when={apps() !== null}
        fallback={
          <div class="px-5 py-4">
            <Banner kind="info" message={t('wasmNotCompiled') as string} />
          </div>
        }
      >
        <Show when={tab.error()}>
          <div class="px-5 pt-4">
            <Banner kind="error" message={tab.error() ?? undefined} />
          </div>
        </Show>
        <div class="divide-y divide-[var(--color-border-subtle)] mt-2">
          <StaticConfigBlock title={t('wasmSectionTrust') as string}>
            <div class="grid gap-3 sm:grid-cols-2 pt-2">
              <TextArea
                full
                label={t('wasmTrustedKeys')}
                hint={t('wasmTrustedKeysHint') as string}
                inputClass="min-h-[96px]"
                value={tab.form.trusted_keys}
                onInput={(event) => tab.setForm('trusted_keys', event.currentTarget.value)}
              />
              <TextInput
                label={t('wasmUpdateCheckTime')}
                placeholder="03:30"
                hint={t('wasmUpdateCheckTimeHint') as string}
                error={timeInvalid() ? (t('wasmUpdateCheckInvalid') as string) : undefined}
                value={tab.form.update_check_time}
                onInput={(event) => tab.setForm('update_check_time', event.currentTarget.value)}
              />
              <div class="flex items-center">
                <Switch
                  checked={tab.form.allow_unsigned === 'true'}
                  onChange={(checked) => tab.setForm('allow_unsigned', checked ? 'true' : 'false')}
                  label={t('wasmAllowUnsigned') as string}
                  hint={t('wasmAllowUnsignedHint') as string}
                />
              </div>
            </div>
          </StaticConfigBlock>
        </div>
        <SavePanel
          dirty={tab.dirty()}
          saving={tab.saving()}
          onSave={() => handleSave().catch(() => undefined)}
          onDiscard={tab.discard}
          note={t('restartHint') as string}
        />
        <div class="border-t border-[var(--color-border-subtle)]">
          <div class="flex items-center gap-3 py-3 px-5">
            <span class="flex-1 text-[0.9rem] font-semibold text-[var(--color-text-primary)]">
              {t('wasmSectionApps')}
            </span>
            <Button size="sm" variant="secondary" onClick={() => void loadApps()}>
              {t('wasmRefresh')}
            </Button>
          </div>
          <div class="flex flex-col gap-3 px-5 pb-4">
            <Banner kind="info" message={t('wasmInstallHint') as string} />
            <Show when={appsError()}>
              <Banner kind="error" message={appsError() ?? undefined} />
            </Show>
            <Show when={apps()?.length === 0 && !appsError()}>
              <p class="m-0 text-[0.85rem] text-[var(--color-text-muted)]">{t('wasmNoApps')}</p>
            </Show>
          </div>
          <div class="divide-y divide-[var(--color-border-subtle)] border-t border-[var(--color-border-subtle)]">
            {/* Keyed by name so a refresh keeps open rows and loaded settings. */}
            <Key each={apps() ?? []} by={(app) => app.name}>
              {(app) => <AppRow app={app()} onChanged={loadApps} />}
            </Key>
          </div>
        </div>
      </Show>
      <RestartConfirmModal
        open={confirmOpen()}
        onClose={() => setConfirmOpen(false)}
        onConfirm={() => {
          setConfirmOpen(false);
          props.onRestartRequest();
        }}
        subtitle={t('restartHint') as string}
      />
    </TabShell>
  );
};
