# -*- mode: python -*-

block_cipher = None

added_files = [
    ('README.md', '.'),
]
a = Analysis(['typtop/typtops.py'],
             pathex=['/home/rahul/projects/pam-typopw'],
             binaries=[],
             datas=added_files,
             hiddenimports=['word2keypress.adjacency_graphs'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='typtop',
          debug=False,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='typtops')
