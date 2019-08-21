#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}

DOCUMENTATION = r'''
---
module: acl
version_added: '1.4'
short_description: Set and retrieve file ACL information.
description:
  - Set and retrieve file ACL information.
  - Please not: special escape sequences, like '\r', '\n' etc should be escaped as well
options:
  path:
    description:
    - The full path of the file or object.
    type: path
    required: yes
    aliases: [ name ]
  state:
    description:
    - Define whether the ACL should be present or not.
    - The C(query) state gets the current ACL without changing it, for use in C(register) operations.
    - The C(absent) state with specified C(path) and without C(entry) or C(etype) deletes all ACLs of a specified C(path)
    choices: [ absent, present, query ]
    default: query
  follow:
    description:
    - Whether to follow symlinks on the path if a symlink is encountered.
    type: bool
    default: yes
  default:
    description:
    - If the target is a directory, setting this to C(yes) will make it the default ACL for entities created inside the directory.
    - Setting C(default) to C(yes) causes an error if the path is a file.
    type: bool
    default: no
    version_added: '1.5'
  entity:
    description:
    - The actual user or group that the ACL applies to when matching entity types user or group are selected.
    version_added: '1.5'
  etype:
    description:
    - The entity type of the ACL to apply, see C(setfacl) documentation for more info.
    - owner@, group@, everyone@ - NFSv4 definitions of POSIX counterparts (valid for FreeBSD/FreeNAS ZFS ACLs)
    choices: [ user, group, other, mask, owner@, group@, everyone@ ]
    version_added: '1.5'
  permissions:
    description:
    - On Linux or FreeBSD, the basic permissions to apply/remove can be any combination of C(r), C(w) and C(x) (read, write and execute respectively)
    - if C(use_nfsv4_acls) is set to C(true), for the possible values of C(permissions) on FreeBSD please refer to C(setfacl(1)) part C(NFSv4 ACL ENTRIES).
    version_added: '1.5'
  entry:
    description:
    - DEPRECATED.
    - The ACL to set or remove.
    - This must always be quoted in the form of C(<etype>:<qualifier>:<perms>).
    - The qualifier may be empty for some types, but the type and perms are always required.
    - C(-) can be used as placeholder when you do not care about permissions.
    - This is now superseded by entity, type and permissions fields.
  recursive:
    description:
    - Recursively sets the specified ACL.
    - Available on FreeBSD starting from FreeBSD 12
    - Incompatible with C(state=query).
    type: bool
    default: no
    version_added: '2.0'
  recalculate_mask:
    description:
    - Select if and when to recalculate the effective right masks of the files.
    - See C(setfacl) documentation for more info.
    - Incompatible with C(state=query).
    - Linux-only
    choices: [ default, mask, no_mask ]
    default: default
    version_added: '2.7'
  reset:
    description:
    - removes all extended ACL entries
    - the base ACL entries of the owner, group and others are retained.
    type: bool
    default: 'no'
    version_added: '2.8'
  use_nfsv4_acls:
    description:
    - Use NFSv4 ACLs instead of POSIX ACLs.
    - necessary to set ACLs on FreeBSD ZFS file systems
    type: bool
    default: no
    version_added: '2.2'

author:
- Brian Coca (@bcoca)
- Jérémie Astori (@astorije)
- Mike Grozak (@rhaido)
notes:
- The C(acl) module requires that ACLs are enabled on the target filesystem and that the C(setfacl) and C(getfacl) binaries are installed.
- This module only supports Linux and FreeBSD distributions.
- Certain functionality is Linux-specific and not available anywhere else - please read descriptions carefully.
- As of Ansible 2.3, the I(name) option has been changed to I(path) as default, but I(name) still works as well.
'''

EXAMPLES = r'''
- name: Grant user Joe read access to a file
  acl:
    path: /etc/foo.conf
    entity: joe
    etype: user
    permissions: r
    state: present

- name: Removes the ACL for Joe on a specific file
  acl:
    path: /etc/foo.conf
    entity: joe
    etype: user
    state: absent

- name: Sets default ACL for joe on /etc/foo.d/
  acl:
    path: /etc/foo.d/
    entity: joe
    etype: user
    permissions: rw
    default: yes
    state: present

- name: Same as previous but using entry shorthand
  acl:
    path: /etc/foo.d/
    entry: default:user:joe:rw-
    state: present

- name: Obtain the ACL for a specific file
  acl:
    path: /etc/foo.conf
  register: acl_info

- name: strip all ACLs from a directory
  acl:
    path: /mnt/tank/data/foo.dir
    state: absent

- name: NFS4 ACLs/FreeNAS/FreeBSD - reset all ACLs before applying new ones
  acl:
    path: /mnt/tank/data/foo2.dir
    etype: user
    entity: foo
    permissions: "full_set:file_inherit/dir_inherit"
    use_nfsv4_acls: true
    reset: yes
    state: present
'''

RETURN = r'''
acl:
    description: Current ACL on provided path (after changes, if any)
    returned: success
    type: list
    sample: [ "user::rwx", "group::rwx", "other::rwx" ]
'''

import os

from ansible.module_utils.basic import AnsibleModule, get_platform
from ansible.module_utils._text import to_native


def split_entry(entry):
    ''' splits entry and ensures normalized return'''

    a = entry.split(':')

    d = None
    if entry.lower().startswith("d"):
        d = True
        a.pop(0)

    if len(a) == 2:
        a.append(None)

    t, e, p = a
    t = t.lower()

    if t.startswith("u"):
        t = "user"
    elif t.startswith("g"):
        t = "group"
    elif t.startswith("m"):
        t = "mask"
    elif t.startswith("o"):
        t = "other"
    else:
        t = None

    return [d, t, e, p]


def build_entry(etype, entity, permissions=None, use_nfsv4_acls=False):
    '''Builds and returns an entry string. Does not include the permissions bit if they are not provided.'''
    if use_nfsv4_acls:
        if get_platform().lower() == 'freebsd' and etype in ('owner@', 'group@', 'everyone@'):
            return ':'.join([etype, permissions, 'allow'])
        else:
            return ':'.join([etype, entity, permissions, 'allow'])

    if permissions:
        return etype + ':' + entity + ':' + permissions

    return etype + ':' + entity


def build_command(module, mode, path, follow, default, recursive, recalculate_mask, reset, entry=''):
    '''Builds and returns a getfacl/setfacl command.'''
    if mode in ('set', 'rm'):
        cmd = [module.get_bin_path('setfacl', True)]

        if recursive:
            '''starting from FreeBSD 12 setfacl supports recursive option (-R)'''
            if get_platform().lower() == 'linux':
                cmd.append('--recursive')
            if get_platform().lower() == 'freebsd':
                cmd.append('-R')

    if mode == 'set':
        '''Discard all ACL if reset option is set.'''
        if reset:
            cmd.append('-b')
        cmd.append('-m "%s"' % entry)

    elif mode == 'rm':
        if reset:
            '''If we already reset everything, no need to be precise'''
            cmd.append('-b')
        else:
            cmd.append('-x "%s"' % entry)
    else:  # mode == 'get'
        cmd = [module.get_bin_path('getfacl', True)]
        # prevents absolute path warnings and removes headers
        if get_platform().lower() == 'linux':
            cmd.append('--omit-header')
            cmd.append('--absolute-names')

    if not follow:
        if get_platform().lower() == 'linux':
            cmd.append('--physical')
        elif get_platform().lower() == 'freebsd':
            cmd.append('-h')

    if default:
        cmd.insert(1, '-d')

    '''Linux-specific functionality'''
    if get_platform().lower() == 'linux':
        if recalculate_mask == 'mask' and mode in ['set', 'rm']:
            cmd.append('--mask')
        elif recalculate_mask == 'no_mask' and mode in ['set', 'rm']:
            cmd.append('--no-mask')

    cmd.append(path)
    return cmd


def acl_changed(module, cmd):
    '''Returns true if the provided command affects the existing ACLs, false otherwise.'''
    # FreeBSD do not have a --test flag, so by default, it is safer to always say "true"
    if get_platform().lower() == 'freebsd':
        return True

    cmd = cmd[:]  # lists are mutables so cmd would be overwritten without this
    cmd.insert(1, '--test')
    lines = run_acl(module, cmd)

    for line in lines:
        if not line.endswith('*,*'):
            return True
    return False


def run_acl(module, cmd, check_rc=True):

    try:
        (rc, out, err) = module.run_command(' '.join(cmd), check_rc=check_rc)
    except Exception as e:
        module.fail_json(msg=to_native(e))

    lines = []
    for l in out.splitlines():
        if not l.startswith('#'):
            lines.append(l.strip())

    if lines and not lines[-1].split():
        # trim last line only when it is empty
        return lines[:-1]

    return lines


def main():
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='path', required=True, aliases=['name']),
            entry=dict(type='str'),
            entity=dict(type='str', default=''),
            etype=dict(
                type='str',
                choices=['user', 'group', 'other', 'mask', 'owner@', 'group@', 'everyone@'],
            ),
            permissions=dict(type='str'),
            state=dict(
                type='str',
                default='query',
                choices=['query', 'present', 'absent'],
            ),
            follow=dict(type='bool', default=True),
            default=dict(type='bool', default=False),
            recursive=dict(type='bool', default=False),
            recalculate_mask=dict(
                type='str',
                default='default',
                choices=['default', 'mask', 'no_mask'],
            ),
            reset=dict(type='bool', default=False),
            use_nfsv4_acls=dict(type='bool', default=False)
        ),
        supports_check_mode=True,
    )

    if get_platform().lower() not in ['linux', 'freebsd']:
        module.fail_json(msg="The acl module is not available on this system.")

    path = module.params.get('path')
    entry = module.params.get('entry')
    entity = module.params.get('entity')
    etype = module.params.get('etype')
    permissions = module.params.get('permissions')
    state = module.params.get('state')
    follow = module.params.get('follow')
    default = module.params.get('default')
    recursive = module.params.get('recursive')
    recalculate_mask = module.params.get('recalculate_mask')
    reset = module.params.get('reset')
    use_nfsv4_acls = module.params.get('use_nfsv4_acls')

    if not os.path.exists(path):
        module.fail_json(msg="Path not found or not accessible.")

    if state == 'query':
        if recursive:
            module.fail_json(msg="'recursive' MUST NOT be set when 'state=query'.")

        if recalculate_mask in ['mask', 'no_mask']:
            module.fail_json(msg="'recalculate_mask' MUST NOT be set to 'mask' or 'no_mask' when 'state=query'.")

        if reset:
            module.fail_json(msg="'reset' MUST NOT be set when 'state=query'.")

    if not entry:
        if state == 'absent':
            if permissions:
                module.fail_json(msg="'permissions' MUST NOT be set when 'state=absent'.")
            if reset and etype:
                module.fail_json(msg="'reset' can not be used together with explicit removal of ACLs")

        if state == 'present' and not etype:
            module.fail_json(msg="'etype' MUST be set when 'state=%s'." % state)

    if entry:
        if etype or entity or permissions:
            module.fail_json(msg="'entry' MUST NOT be set when 'entity', 'etype' or 'permissions' are set.")

        if state == 'present' and not entry.count(":") in [2, 3]:
            module.fail_json(msg="'entry' MUST have 3 or 4 sections divided by ':' when 'state=present'.")

        if state == 'absent':
            if not entry.count(":") in [1, 2]:
                module.fail_json(msg="'entry' MUST have 2 or 3 sections divided by ':' when 'state=absent'.")
            if reset:
                module.fail_json(msg="'entry' can not be used together with 'state=absent' and 'reset=yes'")

        if state == 'query':
            module.fail_json(msg="'entry' MUST NOT be set when 'state=query'.")

        default_flag, etype, entity, permissions = split_entry(entry)
        if default_flag is not None:
            default = default_flag

    changed = False
    msg = ""

    if state == 'present':
        entry = build_entry(etype, entity, permissions, use_nfsv4_acls)
        command = build_command(
            module, 'set', path, follow,
            default, recursive, recalculate_mask, reset, entry
        )
        changed = acl_changed(module, command)

        if changed and not module.check_mode:
            run_acl(module, command)
        msg = "%s is present" % entry

    elif state == 'absent':
        if not entry and not etype:
            reset = True
            command = build_command(
                module, 'rm', path, follow,
                default, recursive, recalculate_mask, reset
            )
        else:
            entry = build_entry(etype, entity, use_nfsv4_acls)
            command = build_command(
                module, 'rm', path, follow,
                default, recursive, recalculate_mask, reset, entry
            )

        changed = acl_changed(module, command)

        if changed and not module.check_mode:
            run_acl(module, command, False)
        msg = "%s is absent" % entry

    elif state == 'query':
        msg = "current acl"

    acl = run_acl(
        module,
        build_command(module, 'get', path, follow, default, recursive, recalculate_mask, reset)
    )

    module.exit_json(changed=changed, msg=msg, acl=acl)


if __name__ == '__main__':
    main()
