# Android Overrides

This directory holds the subset of files under `src-tauri/gen/android/`
that have been hand-customized away from what `tauri android init`
regenerates by default.

`src-tauri/gen/` is gitignored because the Tauri CLI treats it as a
generated build output — the exact layout can change between Tauri
versions and is supposed to be rebuilt from scratch. But a handful
of files inside it hold platform-specific customizations that we
*do* care about keeping:

| File | Customization |
|---|---|
| `app/src/main/AndroidManifest.xml` | `android:screenOrientation="portrait"` (lock orientation), `android:windowSoftInputMode="adjustResize"` (so `env(keyboard-inset-height)` reports correctly when the IME opens) |
| `app/src/main/res/values/themes.xml` | `windowBackground = @drawable/splash` (cold-start splash), `statusBarColor` + `navigationBarColor` set to the brand dark so the system chrome blends into the splash |
| `app/src/main/res/drawable/splash.xml` | Layer-list: dark brand background + centered launcher foreground — shown while the Tauri WebView is initializing |
| `app/src/main/res/values/colors.xml` | `ic_launcher_background = #07080a` (the brand dark used by the adaptive icon and the splash) |

## Restoring after a regen

If you ever delete `src-tauri/gen/` or Tauri regenerates it (e.g.
after a Tauri version bump), run:

```bash
bun scripts/apply-android-overrides.mjs
```

Or manually copy the tree over the regenerated one:

```bash
cp -r src-tauri/android-overrides/app/src/main/* \
      src-tauri/gen/android/app/src/main/
```

The build scripts (`tauri:android:build`) run this automatically.
