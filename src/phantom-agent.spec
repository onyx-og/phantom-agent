# phantom-agent.spec
block_cipher = None

a = Analysis(
    ['src/phantom_agent.py'],
    pathex=[],
    binaries=[],
    datas=[('src/config.json', '.')],  # include config
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)
exe = EXE(
    a.pure, a.scripts, a.binaries, a.zipfiles, a.datas,
    name='phantom-agent',
    console=True
)
