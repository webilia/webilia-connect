<?php

namespace Webilia\Connect\WordPress;

use Webilia\Connect\Client;
use Webilia\Connect\Contracts\UpdateClient as UpdateClientContract;
use Webilia\Connect\Exception\TransientException;

final class UpdateClient implements UpdateClientContract
{
    private Client $connect;
    private string $integration;
    private string $version;
    private string $basename;
    private string $coreVersion;
    private string $slug;
    private string $updateCapability;
    /** @var callable|null */
    private $fallback;
    private bool $informationResolved = false;
    /** @var array<string, mixed>|null */
    private ?array $information = null;

    /**
     * @param callable(): array<string, mixed>|object|false|null $fallback
     */
    public function __construct(Client $connect, string $integration, string $version, string $basename, string $coreVersion = '', string $updateCapability = '', ?callable $fallback = null)
    {
        $this->connect = $connect;
        $this->integration = $integration;
        $this->version = $version;
        $this->basename = $basename;
        $this->coreVersion = $coreVersion;
        $this->updateCapability = $updateCapability !== '' ? $updateCapability : $integration.'.update';
        $this->fallback = $fallback;
        $directory = trim(dirname($basename), '.');
        $this->slug = $directory !== ''
            ? basename($directory)
            : pathinfo(basename($basename), PATHINFO_FILENAME);

        add_filter('pre_set_site_transient_update_plugins', [$this, 'checkUpdate']);
        add_filter('plugins_api', [$this, 'checkInfo'], 10, 3);
    }

    public function checkUpdate($transient)
    {
        if (empty($transient->checked)) {
            return $transient;
        }

        $info = $this->information();
        if (! $info || empty($info['new_version']) || empty($info['download_link']) || version_compare($this->version, (string) $info['new_version'], '>=')) {
            return $transient;
        }

        $update = (object) [
            'slug' => $this->slug,
            'plugin' => $this->basename,
            'new_version' => $info['new_version'],
            'url' => $info['url'] ?? '',
            'package' => $info['download_link'] ?? '',
            'tested' => $info['tested'] ?? '',
            'requires' => $info['requires'] ?? '',
            'requires_php' => $info['requires_php'] ?? '',
            'icons' => (array) ($info['icons'] ?? []),
        ];
        $transient->response[$this->basename] = $update;

        return $transient;
    }

    public function checkInfo($false, $action, $arg)
    {
        if ($action !== 'plugin_information' || ($arg->slug ?? '') !== $this->slug) {
            return $false;
        }

        $info = $this->information();
        if (! $info) {
            return $false;
        }

        $info['slug'] = $info['slug'] ?? $this->slug;
        $info['icons'] = (array) ($info['icons'] ?? []);
        $info['sections'] = (array) ($info['sections'] ?? []);

        return (object) $info;
    }

    /** @return array<string, mixed>|null */
    private function information(): ?array
    {
        if ($this->informationResolved) {
            return $this->information;
        }

        $this->informationResolved = true;

        try {
            // The updates endpoint verifies the default update capability itself.
            // Preserve custom capabilities, whose intent the endpoint cannot infer.
            if ($this->updateCapability !== $this->integration.'.update') {
                $authorization = $this->connect->authorize($this->integration, $this->updateCapability);
                if (! $authorization->allowed()) {
                    return $this->fallbackInformation();
                }
            }

            $update = $this->connect->update($this->integration, $this->basename, $this->version, $this->coreVersion);

            if (($update['allowed'] ?? null) === true) {
                return $this->information = $update;
            }
        } catch (TransientException $exception) {
            // The legacy updater uses the same API infrastructure. Let WordPress
            // retry later instead of sending a second request during an outage.
            return null;
        } catch (\Throwable $exception) {
            // A connected account may not own every installed product. Let the
            // host application preserve its legacy update channel in that case.
        }

        return $this->fallbackInformation();
    }

    /** @return array<string, mixed>|null */
    private function fallbackInformation(): ?array
    {
        if (! is_callable($this->fallback)) {
            return null;
        }

        try {
            $fallback = call_user_func($this->fallback);
            if (is_object($fallback)) {
                $fallback = get_object_vars($fallback);
            }

            return is_array($fallback) ? $this->information = $fallback : null;
        } catch (\Throwable $exception) {
            return null;
        }
    }
}
