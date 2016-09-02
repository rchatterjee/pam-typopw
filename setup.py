from distutils.core import setup

# With the help from http://peterdowns.com/posts/first-time-with-pypi.html

setup(
  name = 'loginwitherror',
  packages = ['loginwitherror'], # this must be the same as the name above
  version = '1.0',
  description = 'Adaptive Typo Tolerance for Ubuntu login screen',
  author = 'Rahul Chatterjee, Yuval Pnueli',
  author_email = 'rc737@cornell.edu',
  url = 'https://github.com/rchatterjee/pam-typopw', # URL in github repo
  download_url = 'https://github.com/rchatterjee/pam-typopw/tarball/v1.0',
  keywords = [
      'Password', 'typo-tolerance', 
      'login-with-errors', 'Login'
  ],
  classifiers = [],
)
