## Update:
Sample install script (`install.sh`) has been added. You can instal this moduel by just running the following command.
```bash
$ sudo bash install.sh
```
The following is not required, but left here only for information purpose.

### How to set it up?

1. First create a file named `test` in your `/etc/pam.d` folder. (You will need sudo for that.)
2. Write the following line in the file
```
auth sufficient pam_python.so <path to your this directory>/pam_typotolerant.py 
```
3. Install `libpam-python` from apt-get repository. 
```bash
$ sudo apt-get install libpam-python
```
4. Install `mistypography` and `pwmodel` python modlues. **I am working removing them from this
   or add them statically.**

