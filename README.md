# Webilia Connect

Webilia Connect is the shared connection SDK for Webilia WordPress products.

Each product ships a scoped build of this package, but every build uses the same
site-wide `webilia_connect_connection` record and the same API protocol. Do not
log the connection credential or expose it in plugin UI.

## Credential encryption

The connection credential is encrypted before it is stored in WordPress. Set a
unique `WEBILIA_CONNECT_KEY` constant in `wp-config.php` to manage that key
material explicitly. Otherwise, the SDK creates a protected
`.webilia-connect-key.php` file in `WP_CONTENT_DIR`; retain that file when
migrating the site. The encryption key is never stored in `wp_options`.

For a multiple-node deployment, define the same `WEBILIA_CONNECT_KEY` value on
every node unless `WP_CONTENT_DIR` is shared. The local key-file fallback is
only suitable for a single node or shared content storage.

## Release compatibility

The Composer source namespace is `Webilia\\Connect`. WordPress product releases
must scope bundled vendor namespaces (for example with PHP-Scoper) before
distribution so independently updated products cannot load incompatible SDK
classes in one request. The option names and HTTP protocol are intentionally
unscoped and stable.

The stable contracts are under `Webilia\\Connect\\Contracts`: `Connection`,
`Capability`, `AuthorizationResult`, `UpdateClient`, `Storage`, and `HttpClient`.
Storage adapters that can atomically compare and replace the encrypted connection
record should additionally implement `ConditionalConnectionStorage`; the bundled
WordPress adapter does so to protect concurrent callbacks and disconnects.
Pass the product's update capability to `WordPress\\UpdateClient`; when omitted,
the adapter uses the conventional `{integration}.update` capability name.

## On-demand status checks

WordPress products can use `new WordPress\\ConnectionStatus($client)` and call
`isConnected()` when a page needs a verified connection state. Successful
checks are cached for five minutes across requests. A transient API failure
keeps the local connection and delays the next status attempt by 60–120 seconds.
Call `ConnectionStatus::clearCache()` after a completed connection or disconnect.
Constructing the helper does not contact the API; `Client::verifyConnection()`
remains the direct, uncached check.

The HTTP adapter treats a non-JSON `403` from upstream infrastructure as
transient. JSON application `403` responses remain request errors, so product
denials can still use a configured legacy update fallback.

## Versioning and consumer releases

The package follows semantic versioning. A minor or patch release must retain
the public contracts, option format, and API protocol; breaking changes require
a new major version. Release a tagged package version, install that version in
the consumer with Composer, then run the product's namespace-scoping build so
each distributed plugin owns a prefixed copy of the PHP classes. Do not ship
the unscoped shared namespace in a WordPress release.
