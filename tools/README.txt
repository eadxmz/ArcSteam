ArcSteam Helper Binaries
========================
Place these 4 lightweight CLI binaries inside this tools/ folder next to arcsteam.exe:

1. innounp.exe      - Inno Setup Unpacker (extracts setup.exe {tmp} plugins & install_script.iss)
2. unarc.exe        - FreeArc CLI decompressor (runs FitGirl / DODI / R.G. Mechanics / ElAmigos)
3. innoextract.exe  - Pure Inno Setup extractor (streams GOG builds like Silksong directly)
4. 7z.exe (+ 7z.dll)- 7-Zip CLI (handles .7z, .rar, .zip, .iso, and Portable/Scene releases)

Runtime Prerequisite (for Live Torrent-to-Unpack Virtual Drive Z:\):
- Install WinFsp 2.1+ MSI from https://winfsp.dev/
- Run arcsteam.exe as Administrator to enable automatic Windows Defender RAII exclusions.
