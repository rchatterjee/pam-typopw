# -*- mode: python -*-

block_cipher = None

import zxcvbn, Crypto

import os, sys
zxcvbn_path = os.path.dirname(zxcvbn.__file__)
crypto_path = os.path.dirname(Crypto.__file__)

a = Analysis(['pam_typotolerant.py'],
             pathex=['/home/rahul/projects/pam-typopw'],
             binaries=[(crypto_path, 'site-packages/Crypto/')],
             datas=[('{}/generated/'.format(zxcvbn_path), 
                     'zxcvbn/generated/')],
             hiddenimports=[],
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
          name='pam_typotolerant',
          debug=True,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='pam_typotolerant')
