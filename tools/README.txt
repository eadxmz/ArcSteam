ArcSteam Helper Binaries
========================
Place these CLI binaries inside this tools/ folder next to arcsteam.exe:

1. innounp.exe       - Inno Setup Unpacker (extracts setup.exe {tmp} plugins & install_script.iss)
2. unarc.exe         - FreeArc CLI decompressor (FitGirl / DODI / R.G. Mechanics / ElAmigos)
3. srep64.exe        - [RECOMMENDED] 64-bit SuperREP binary (lets 32-bit unarc.exe safely scale
                       past 2 GB RAM up to 65% of system memory without 32-bit OOM crashes)
4. innoextract.exe   - Pure Inno Setup extractor (streams GOG builds directly)
5. 7z.exe (+ 7z.dll) - 7-Zip CLI (handles .7z, .rar, .zip, .iso, and Portable/Scene releases)

Runtime Prerequisite (for Live Torrent-to-Unpack Virtual Drive Z:\):
- Install WinFsp 2.1+ MSI from https://winfsp.dev/
- Run arcsteam.exe as Administrator to enable crash-safe Windows Defender exclusions.
