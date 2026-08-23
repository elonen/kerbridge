# syntax=docker/dockerfile:1
# Cross-compile the Windows client in Docker, so a Linux host with only Docker --
# no local Rust, no MinGW -- can build the shipping .exes. Emits both: the CLI
# (kerbridge.exe) and the tray (kerbridge-agent.exe), which link the same core.
#
# Mirrors client/.cargo/config.toml: target x86_64-pc-windows-gnu, linked
# by MinGW-w64, never MSVC. Debian base (not the Alpine one the server images
# use) because MinGW ships as Debian's `mingw-w64` metapackage -- gcc + binutils,
# the latter providing the `windres` that this crate's build.rs needs to compile
# its .rc (app manifest + icon). native-tls resolves to SChannel on the Windows
# target, so there is no OpenSSL to cross-build.
#
# Build context is the repository root; the whole client workspace is copied,
# since the agent depends on ../kerbridge-client by path and both resolve through
# one lockfile. See the top-level Makefile's `windows` target.
FROM rust@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c AS build
RUN apt-get update \
 && apt-get install -y --no-install-recommends mingw-w64 \
 && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-pc-windows-gnu
WORKDIR /src
COPY client ./client
# Two builds, one per crate directory. The target is named here rather than
# pinned per crate, because the core builds for the host too; the linker comes
# from client/.cargo/config.toml. They share the workspace target directory, so
# the second links the core the first already compiled.
RUN cd client/kerbridge-client && cargo build --release --target x86_64-pc-windows-gnu
RUN cd client/kerbridge-agent-windows && cargo build --release --target x86_64-pc-windows-gnu

# Export stage: `docker build --target dist --output <dir>` writes only the two
# .exes to the host -- scratch means the output directory gets nothing else.
FROM scratch AS dist
COPY --from=build /src/client/target/x86_64-pc-windows-gnu/release/kerbridge.exe /
COPY --from=build /src/client/target/x86_64-pc-windows-gnu/release/kerbridge-agent.exe /

# ---- the MSI ---------------------------------------------------------------
# wixl (GNOME msitools), which implements the MSI format natively on Linux -- so
# the whole chain (compile, package, and later sign) stays on a Linux runner and
# no Windows machine is involved.
#
# NOT the WiX Toolset, which the plan originally specified: WiX writes the MSI
# database through the Windows Installer API and dies on a missing msi.dll on any
# non-Windows host, even for a package containing no files. That is a hard stop,
# not a version or an architecture problem -- it reproduces on WiX 5 and 6, and on
# amd64 as well as arm64. wixl builds the same package with no Windows anywhere.
#
# Same debian trixie digest as the server images. The .wxs is files + registry
# only; a build-time custom action would need Win32 code and would break exactly
# this.
FROM debian@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd AS msi
RUN apt-get update \
 && apt-get install -y --no-install-recommends wixl msitools \
 && rm -rf /var/lib/apt/lists/*
# The MSI ProductVersion. Passed in by the Makefile from the agent crate's
# Cargo.toml; the default only exists so a bare `docker build` of this stage still
# produces something, and it is a version no release will ever carry.
ARG VERSION=0.0.0
WORKDIR /pkg
COPY --from=build /src/client/target/x86_64-pc-windows-gnu/release/kerbridge.exe .
COPY --from=build /src/client/target/x86_64-pc-windows-gnu/release/kerbridge-agent.exe .
COPY client/kerbridge-agent-windows/ui/icons/app-icon.ico .
COPY client/kerbridge-agent-windows/installer/nas-access.wxs .
COPY client/kerbridge-agent-windows/installer/ui ./ui
COPY LICENSE .
RUN mkdir /out && wixl -a x64 \
      -D Version="$VERSION" \
      -D TrayExe=kerbridge-agent.exe \
      -D CliExe=kerbridge.exe \
      -D IconFile=app-icon.ico \
      -D LicenseDoc=LICENSE \
      -o /out/kerbridge-nas-access.msi nas-access.wxs

# The rows wixl cannot author, written straight into the built database. msibuild
# is msitools' table editor, so this needs no second toolchain.
#
# 1-8: the two dialogs (nas-access.wxs, @"completion dialog" and @"files in use").
#      wixl has no UI authoring whatsoever -- <UI>, <Dialog> and <UIRef> are all
#      rejected by its parser -- so the UI tables are imported verbatim from
#      installer/ui/, and the row that shows the completion dialog is appended to
#      the InstallUISequence wixl did write. Sequence -1 is Windows Installer's
#      "successful completion" slot, which is also why that dialog cannot be an
#      ordinary sequenced action. MsiRMFilesInUse needs no sequence row at all:
#      the installer raises it by name when a file is in use.
#      ListBox is imported with no rows on purpose -- MsiRMFilesInUse's process
#      list is a ListBox control, which the installer fills from FileInUseProcess
#      at run time, but the table it is bound to has to exist.
# 9-11: the REMOVESETTINGS cleanup (nas-access.wxs, component SettingsCleanup). wixl
#      has no RemoveFile element at all, and ignores RemoveFolder/@Property -- it
#      would aim the folder row at INSTALLFOLDER, deleting the wrong directory.
#      InstallMode 2 is msidbRemoveFileInstallModeOnRemove; a NULL FileName means
#      "the directory itself, if it ends up empty".
# 12:  AUTOSTART and REMOVESETTINGS have to survive the hand-off to the elevated
#      execute sequence. wixl parses Property/@Secure and then does nothing with
#      it, populating SecureCustomProperties only from MajorUpgrade -- so read back
#      what it wrote and append ours rather than hardcoding its two WIX_* names.
RUN set -eu; \
    msibuild /out/kerbridge-nas-access.msi \
      -i ui/TextStyle.idt \
      -i ui/Dialog.idt \
      -i ui/Control.idt \
      -i ui/ControlEvent.idt \
      -i ui/ControlCondition.idt \
      -i ui/RadioButton.idt \
      -i ui/ListBox.idt \
      -q "INSERT INTO \`InstallUISequence\` (\`Action\`, \`Sequence\`) VALUES ('ExitDialog', -1)" \
      -q "INSERT INTO \`RemoveFile\` (\`FileKey\`, \`Component_\`, \`FileName\`, \`DirProperty\`, \`InstallMode\`) VALUES ('RemoveSettingsConfig', 'SettingsCleanup', 'config.toml', 'SETTINGSFOLDER', 2)" \
      -q "INSERT INTO \`RemoveFile\` (\`FileKey\`, \`Component_\`, \`FileName\`, \`DirProperty\`, \`InstallMode\`) VALUES ('RemoveSettingsLogs', 'SettingsCleanup', '*.log', 'SETTINGSFOLDER', 2)" \
      -q "INSERT INTO \`RemoveFile\` (\`FileKey\`, \`Component_\`, \`DirProperty\`, \`InstallMode\`) VALUES ('RemoveSettingsFolder', 'SettingsCleanup', 'SETTINGSFOLDER', 2)"; \
    secure=$(msiinfo export /out/kerbridge-nas-access.msi Property | awk -F'\t' '$1 == "SecureCustomProperties" { print $2 }'); \
    msibuild /out/kerbridge-nas-access.msi \
      -q "DELETE FROM \`Property\` WHERE \`Property\` = 'SecureCustomProperties'" \
      -q "INSERT INTO \`Property\` (\`Property\`, \`Value\`) VALUES ('SecureCustomProperties', '${secure:+$secure;}AUTOSTART;REMOVESETTINGS')"

# Export stage for the MSI alone: `docker build --target msi-dist --output <dir>`.
# Unsigned -- signing is a release-time act by the publisher (a CI secret), never
# part of a developer build.
FROM scratch AS msi-dist
COPY --from=msi /out/kerbridge-nas-access.msi /
