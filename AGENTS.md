# Opaque public core

This is kcirtapfromspace/opaque. Core libraries, the local broker/CLI/MCP server,
trusted approval verification, independent evidence inspection and local dashboard
belong here. Core must build and operate without private source or enterprise credentials.
Keep public protocols provider-neutral and independently consumable.

Organization SCIM integrations, collaboration delivery adapters, fleet collectors,
enterprise management views and Kubernetes operator implementation belong in the
separate private enterprise repository. Reusability alone does not make code public.
Demo implementation and internal dogfood/research/evidence have separate private homes.
Do not copy private history, configuration, research or runtime records here.

Preserve transactional revocation, durable single-use consumption and explicit unknown
outcomes when changing interfaces. Keep storage drivers out of new wire contracts.
Never commit credentials, keys, local environment/browser state, generated binaries
or raw session artifacts. Use exact source/destination refspecs when pushing branches.
