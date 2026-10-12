import { Show, type Component } from 'solid-js';
import { t } from '../i18n';
import type { AppConfig } from '../api/client';
import { createConfigTab } from '../state/configTab';
import { TabShell } from '../components/layout/TabShell';
import { PageHeader } from '../components/ui/PageHeader';
import { StaticConfigBlock } from '../components/ui/ConfigBlocks';
import { TextInput } from '../components/ui/FormField';
import { SavePanel } from '../components/ui/SavePanel';
import { Banner } from '../components/ui/Banner';

type WebDavForm = {
  webdav_user: string;
  webdav_password: string;
};

export const WebDavPage: Component = () => {
  const tab = createConfigTab<WebDavForm>({
    tab: 'webdav',
    groups: ['webdav'],
    toForm: (config: Partial<AppConfig>) => ({
      webdav_user: config.webdav_user ?? '',
      webdav_password: config.webdav_password ?? '',
    }),
    fromForm: (form) => ({
      webdav_user: form.webdav_user.trim(),
      webdav_password: form.webdav_password,
    }),
    saveMessage: () => t('webdavSaved') as string,
  });

  /* The device returns a mask for a stored password and "" when none is set. */
  const enabled = () => tab.form.webdav_password !== '' && !tab.dirty();
  const mountUrl = () => `https://${window.location.host}/dav/`;

  return (
    <TabShell>
      <PageHeader title={t('navWebDav') as string} description={t('webdavDesc') as string} />
      <Show when={tab.error()}>
        <div class="px-5 pt-4">
          <Banner kind="error" message={tab.error() ?? undefined} />
        </div>
      </Show>
      <div class="divide-y divide-[var(--color-border-subtle)] mt-2">
        <StaticConfigBlock title={t('webdavSection') as string}>
          <div class="flex flex-col gap-3 pt-2">
            <Show when={!tab.loading() && !tab.dirty()}>
              <Banner kind={enabled() ? 'success' : 'info'}>
                <Show when={enabled()} fallback={t('webdavDisabled') as string}>
                  {t('webdavEnabled') as string}{' '}
                  <code class="font-mono select-all">{mountUrl()}</code>
                </Show>
              </Banner>
            </Show>
            <div class="grid gap-3 sm:grid-cols-2">
              <TextInput
                label={t('webdavUser')}
                autocomplete="off"
                value={tab.form.webdav_user}
                onInput={(event) => tab.setForm('webdav_user', event.currentTarget.value)}
              />
              <TextInput
                type="password"
                label={t('webdavPassword')}
                autocomplete="new-password"
                hint={t('webdavPasswordHint') as string}
                value={tab.form.webdav_password}
                onInput={(event) => tab.setForm('webdav_password', event.currentTarget.value)}
              />
            </div>
            <small class="text-[0.72rem] leading-snug text-[var(--color-text-secondary)]/85">
              {t('webdavMountHint') as string}
            </small>
          </div>
        </StaticConfigBlock>
      </div>
      <SavePanel
        dirty={tab.dirty()}
        saving={tab.saving()}
        onSave={() => tab.save().catch(() => undefined)}
        onDiscard={tab.discard}
      />
    </TabShell>
  );
};
