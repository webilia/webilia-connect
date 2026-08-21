<?php

namespace Webilia\Connect\WordPress;

use Webilia\Connect\Client;
use Webilia\Connect\Contracts\UpdateClient as UpdateClientContract;

final class UpdateClient implements UpdateClientContract
{
    private Client $connect;
    private string $integration;
    private string $version;
    private string $basename;
    private string $coreVersion;
    private string $slug;
    private string $updateCapability;

    public function __construct(Client $connect, string $integration, string $version, string $basename, string $coreVersion = '', string $updateCapability = '')
    {
        $this->connect = $connect;
        $this->integration = $integration;
        $this->version = $version;
        $this->basename = $basename;
        $this->coreVersion = $coreVersion;
        $this->updateCapability = $updateCapability !== '' ? $updateCapability : $integration.'.update';
        $parts = explode('/', $basename);
        $this->slug = str_replace('.php', '', (string) end($parts));

        add_filter('pre_set_site_transient_update_plugins', [$this, 'checkUpdate']);
        add_filter('plugins_api', [$this, 'checkInfo'], 10, 3);
    }

    public function checkUpdate($transient)
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        $info = $this->information();
        if (! $info || empty($info['new_version']) || version_compare($this->version, (string) $info['new_version'], '>=')) {
            return $transient;
        }

        $update = (object) [
            'slug' => $this->slug,
            'new_version' => $info['new_version'],
            'url' => $info['url'] ?? '',
            'package' => $info['download_link'] ?? '',
            'tested' => $info['tested'] ?? '',
            'icons' => (array) ($info['icons'] ?? []),
        ];
        $transient->response[$this->basename] = $update;

        return $transient;
    }

    public function checkInfo($false, $action, $arg)
    {
        if (($arg->slug ?? '') !== $this->slug) {
            return $false;
        }

        $info = $this->information();
        if (! $info) {
            return false;
        }

        $info['slug'] = $info['slug'] ?? $this->slug;
        $info['icons'] = (array) ($info['icons'] ?? []);
        $info['sections'] = (array) ($info['sections'] ?? []);

        return (object) $info;
    }

    /** @return array<string, mixed>|null */
    private function information(): ?array
    {
        try {
            $authorization = $this->connect->authorize($this->integration, $this->updateCapability);
            if (! $authorization->allowed()) {
                return null;
            }

            $update = $this->connect->update($this->integration, $this->basename, $this->version, $this->coreVersion);

            return ! empty($update['allowed']) ? $update : null;
        } catch (\Throwable $exception) {
            return null;
        }
    }
}
