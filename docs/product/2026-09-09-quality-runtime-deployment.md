# Quality runtime deployment

Private operator evidence, 2026-09-09. Exclude from visitor HTML, assets, search, sitemaps, and previews. The user explicitly authorized pushing and deploying the merged code.

## Published source and artifacts

| Item | Verified identity |
| --- | --- |
| Private source | `kcirtapfromspace/opaque-dogfood`, `main` at `3b322f24d2743d768406a9ce6e069a9b9f9b0af2` |
| Linux runtime | `192.168.25.201:5050/opaque-hosted-demo@sha256:6f0af6495b7c043532d3d5a41afa525beeed406a2679181517aa249806f5e428` |
| Native executable | Linux/ARM64 `opaque-showcase`, 12,024,864 bytes; SHA-256 `5bfc712879e3d40601d91fcd8386c5e018ec1541bc367729a9f077a59db5b4ff` |
| Builder | Rust 1.95.0; local `rust:1.95.0-slim-bookworm` image ID `sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082` |
| Paused quality Worker | `e0a23462-a1c9-486a-84ae-90678f3a6913` |
| Enabled quality Worker | `853ecf00-64c7-49e3-828b-147730e8f89f` |
| Visitor documentation | Pages deployment `84d94d19-ad8a-4373-acac-a2d606546b84`; [separate exact-artifact and live checks](2026-09-09-visitor-docs-deployment.md) |

The GitHub destination was verified private before pushing. No public repository, repository setting, release tag, or billing plan was changed. GitHub Actions are disabled on the private repository, so remote CI did not run; inherited publication workflows additionally exclude this private repository. The direct deployments above performed publication.

The Linux artifact was built from an exact Git archive of `3b322f2`, using the existing Docker context/cache volumes. Development packages were installed only inside the disposable builder. The checked-in Dockerfile packages the renamed executable and runtime entrypoint. The locally saved tar digest matched the registry digest and the running controller's image ID. Generated binaries and raw operator artifacts remained ignored or in protected temporary storage.

## Tests and rollout

- The merged macOS workspace had 1,957 passing Rust tests, seven intentional ignores, warning-denied all-feature Clippy, formatting, 208 Python passes with two Linux-only skips, 167 Node passes, and generated-site privacy checks. [Merge validation](2026-09-09-quality-extraction-merge-validation.md) distinguishes these checks from earlier evidence.
- The Linux/ARM64 release showcase suite passed 89 unit and 53 gateway tests. One explicitly ignored long-running browser fixture was not counted as executed.
- The actual packaged Python runtime launched `/opt/opaque/bin/opaque-showcase`; its running executable hash matched the artifact. Authenticated health and proxied session returned 200, unauthenticated health returned 401, and readiness was true. This used UID 7383, a read-only root, temporary memory-backed state, dropped capabilities, no new privileges, and no network. No model request or real OAuth credential was used. The disposable container stopped cleanly and its synthetic credential file was removed.

The live demo was already paused. Its authenticated work endpoint returned 200 with zero actions and no next alarm. Slot 0 retained schema 2, generation 28, no lease, and no creation/execution uncertainty. There were no lease Pods or Services. The rollout preserved the slot ConfigMap rather than applying bootstrap state.

The existing guarded renderer produced controller and admission-policy JSON patches from fresh live objects. Both passed server dry-run. The controller patch tested generation, replica count, `Recreate` strategy, image, and the complete prior environment before changing the image and adding references to the existing GitHub OAuth Secret. No credential was rotated or printed. The policy patch tested resource version and the complete prior spec before updating it.

Controller generation 10 became ready with zero restarts on the verified runtime image. Admission-policy generation 10 reported observed generation 10 with no type-check warnings. Server dry-runs accepted both enabled model profiles and rejected the previous runtime image, mismatched model identity, inline OAuth secret, and foreign callback. Host networking was rejected by the existing restricted Pod Security policy before the custom admission policy; that independent rejection is not claimed as custom-policy evidence. These probes did not create Pods.

From the updated controller, authenticated queue polling returned 200 with no work, the GitHub provider configuration was present, and both Gemma and Qwen health endpoints returned 200. Tunnel and model Deployment generations and replica counts were unchanged, including the stopped 14B head and existing RPC workers.

## Public verification and coordination

The enabled quality Worker reported `available:true`, a 600-second session, both approved models, and the checked-in `qwen35-4b` default. Unauthenticated workspace and internal routes returned 401. A foreign-origin join and an invalid same-origin bot proof returned 403. While paused, the same-origin join had returned 503. The live approval callback matched the reviewed 1,256-byte asset exactly, SHA-256 `be92294e9f5ccd526c35757d1b26a37fa51b80e6ce93b7d690a6ddc400c5c354`.

The browser displayed open requests and the Qwen default. Its normal Turnstile verification completed without agent interaction. No demo lease was created during this quality rollout, and no real human OAuth/passkey approval, live task execution, or model completion is claimed by these checks.

A concurrent task, **Investigate Cloudflare usage limit**, was authorized to add polling and storage safeguards. Release ownership was explicitly transferred after the quality rollout checks. That task agreed to preserve the new runtime, OAuth environment, admission policy, frontend/callback, open admissions, Qwen default, Pages deployment, and slot state. Its earlier controller image derived from the old runtime was not deployed. Subsequent safeguard versions and their integration are separate evidence; the Worker identities above identify this quality release, not an assertion that no later version exists.

Temporary build and rollout evidence was retained under `/private/tmp/opaque-showcase-3b322f2-11h_gajx/` and `/private/tmp/opaque-quality-deploy-r7y_6bxz/`. Those paths are operator scratch storage, not a durable archive. Only this sanitized record is committed.
