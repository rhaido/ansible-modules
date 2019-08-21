ansible-modules
===============

specific modules, not for main line

- **acl.py**
patched FreeNAS ACL module, extends ZFS ACL support, adds reset
functionality, adds recursive support (FreeBSD 12+) etc
- **freenas_user.py**
FreeNAS user/group management. As slow as FreeNAS backend servers, as it's
using FreeNAS's REST API. I probably walk faster then they process request, but
there is no that much choice.
- **yum2**
fast YUM module, written in bash
- **apt2**
looks like people know, how to write slow package modules for ansible, thus forcing
us to keep our bash scripts razor-sharp! If seriously, was derived from yum2 the moment I had to
make Debian a usable and maintainable development platform for our company.

