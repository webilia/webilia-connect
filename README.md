# Webilia Connect

Webilia Connect is the shared connection SDK for Webilia WordPress products.

Each product ships a scoped build of this package, but every build uses the same
site-wide `webilia_connect_connection` record and the same API protocol. Do not
log the connection credential or expose it in plugin UI.

## Release compatibility

The Composer source namespace is `Webilia\\Connect`. WordPress product releases
must scope bundled vendor namespaces (for example with PHP-Scoper) before
distribution so independently updated products cannot load incompatible SDK
classes in one request. The option names and HTTP protocol are intentionally
unscoped and stable.

The stable contracts are under `Webilia\\Connect\\Contracts`: `Connection`,
`Capability`, `AuthorizationResult`, `UpdateClient`, `Storage`, and `HttpClient`.
Pass the product's update capability to `WordPress\\UpdateClient`; when omitted,
the adapter uses the conventional `{integration}.update` capability name.

## Versioning and consumer releases

The package follows semantic versioning. A minor or patch release must retain
the public contracts, option format, and API protocol; breaking changes require
a new major version. Release a tagged package version, install that version in
the consumer with Composer, then run the product's namespace-scoping build so
each distributed plugin owns a prefixed copy of the PHP classes. Do not ship
the unscoped shared namespace in a WordPress release.
