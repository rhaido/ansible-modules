#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}

DOCUMENTATION = '''
---
module: freenas_user
version_added: "2.2"
short_description: Manages FreeNAS system users using mixture of builtin-utilities and REST API calls.

description:
    - Manages FreeNAS system users.

options:
  api_user:
    required: true
    description:
      - Username for making authenticated REST API calls

  api_pwd_file:
    required: true
    description:
      - File with a user password used for making authenticated REST API calls

  state:
    required: false
    default: "present"
    choices: [ present, absent ]
    description:
      - Whether the account should exist or not, taking action if the state is different from what is stated.

  name:
    required: true
    description:
      - Name of the user to create, remove or modify.

  uid:
    required: false
    description:
      - Optionally sets the I(UID) of the user.

  group:
    required: false
    description:
      - Optionally sets the user's primary group (takes a group name).

  creategroup:
    required: false
    description:
      - Create a new primary group for the user
    type: bool
    default: 'true'

  home:
    required: true
    default: '/nonexistent'
    description:
      - Sets the user's home directory.

  mode:
    required: false
    description:
      - home directory permissions in the octal form (like 0700 etc)

  gecos:
    required: false
    description:
      - Optionally sets the description (aka I(GECOS)) of user account.

  password:
    required: false
    description:
      - Optionally set the user's password to this plaintext value.
        Beware of security issues.

  pw_disabled:
    required: false
    description:
      - Disables all forms of password login, including for sharing
    type: bool
    default: 'false'
      
  email:
    required: false
    description:
      - An email of a user

  shell:
    required: false
    description:
      - Optionally set the user's shell.
    default: '/usr/local/bin/bash'

  locked:
    description:
      - Lock account
    type: bool
    default: 'false'

  authorized_keys:
    required: false
    description:
      - content of ~/.ssh/authorized_keys

  rmgroup:
    required: false
    description:
      - should the primary group be removed with the account or not

author:
    - Mike Grozak (mike.grozak@gmail.com)

notes:
    - Was tested on FreeNAS 11.3
'''

import os              # various OS facilities
import sys             # to capture the sys.stderr stream output of the executed shell programm
import pwd             # retrieve passwd information
import grp             # retrieve group information
import json            # HTTP REST API calls payload
import platform        # find the hostname of a host
import requests        # to make HTTP REST API call
import subprocess      # to delete users from shell

from ansible.module_utils.basic import AnsibleModule

freenas_version_file = "/etc/version"
changed = False
msg = ""

api_user = ""
api_user_password = ""
api_account_url = ""
api_users_url = ""
api_groups_url = ""

OK = True
FAILURE = False

def dump_text(line):
    with open('/tmp/ansible.log','a') as l:
        l.write(line+'\n\n')

def update_module_msg(text):
    global msg
    msg = msg + text + ";"

def get_user_list():
    try:
        response = requests.get(
            api_users_url,
            auth=(api_user, api_user_password),
            headers={'Content-Type': 'application/json'},
            verify=False,
            data=None)
        response.raise_for_status()
    except:
        update_module_msg("get_user_list(): something is with the API call. Response body: " + response.text)
        return FAILURE

    return json.loads(response.text)

def get_group_data(_g_id):
    try:
        response = requests.get(
                    api_groups_url + str(_g_id) + "/",
                    auth=(api_user, api_user_password),
                    headers={'Content-Type': 'application/json'},
                    verify=False,
                    data=None)
        response.raise_for_status()
    except:
        update_module_msg("get_group_data(): something is wrong with the API call. Response body: " + response.text)
        return FAILURE

    return json.loads(response.text)

def get_group_oid(name):
    try:
        response = requests.get(
                    api_groups_url,
                    auth=(api_user, api_user_password),
                    headers={'Content-Type': 'application/json'},
                    verify=False,
                    data=None)
        response.raise_for_status()
    except:
        update_module_msg("get_group_oid: something went wrong with the API call. Response body: " + response.text)
        return FAILURE

    groups = json.loads(response.text)

    oid = -1

    for g in groups:
        if g["bsdgrp_group"] == name:
            oid = g["id"]
            break

    return oid

def set_api_urls():
    global api_account_url
    global api_users_url
    global api_groups_url

    hostname = platform.node()

    if not hostname or len(hostname) == 0:
        update_module_msg("Hostname of this FreeNAS host is unknown - can not form a proper URL for REST API calls")
        return FAILURE

    api_account_url = "https://" + platform.node() + "/api/v1.0/account"
    api_users_url = api_account_url +  "/users/"
    api_groups_url = api_account_url +  "/groups/"

    return OK

def read_first_line(fname):
    if not os.path.isfile(fname):
        update_module_msg("No such file or not a file at all: " + fname)
        return FAILURE

    try:
        with open(fname, 'r') as f:
            line = f.readline()
    except:
        update_module_msg("Unexpected error while opening and reading a file: " + fname)
        return FAILURE

    return line

def is_freenas():
    v = read_first_line(freenas_version_file)

    if v and v.startswith("FreeNAS"):
        return OK

    update_module_msg("Not a FreeNAS server")
    return FAILURE

def user_exists(name):
    try:
        rc = subprocess.call("grep -q ^" + name + ": /etc/passwd", shell=True)
    except OSError as e:
        print("user_exists(): grep execution failed:", e, file=sys.stderr)
        return FAILURE

    if rc != os.EX_OK:
        return FAILURE

    return OK

def group_exists(name):
    try:
        rc = subprocess.call("grep -q ^" + name + ": /etc/group", shell=True)
    except OSError as e:
        print("group_exists(): grep execution failed:", e, file=sys.stderr)
        return FAILURE

    if rc != os.EX_OK:
        return FAILURE

    return OK

def read_api_pwd (api_pwd_file):
    p = read_first_line(api_pwd_file)

    if not p or len(p) == 0:
        update_module_msg("Error while reading a password from file should be defined")
        return FAILURE

    return p

def api_delete_user (_id):
    try:
        response = requests.delete (api_users_url + str(_id) + "/",
                    auth = (api_user, api_user_password),
                    headers = {'Content-Type': 'application/json'},
                    verify = False)
        response.raise_for_status()
    except:
        update_module_msg("api_delete_user(): something is wrong with the API call. Response body: " + response.text)
        return FAILURE

    return OK

def api_delete_group (_g_id):
    try:
        response = requests.delete(api_groups_url + "/" + str(_g_id) + "/",
                            auth = (api_user, api_user_password),
                            headers = {'Content-Type': 'application/json'},
                            verify = False)
        response.raise_for_status()
    except:
        update_module_msg("api_delete_group(): something is wrong with the API call. Response body: " + response.text)
        return FAILURE

    return OK

def build_group_payload(name, gid, sudo=False):

    if not name or len(name) == 0:
        update_module_msg("Can not create a group payload: name is not defined")

    payload = { 'bsdgrp_group': name }

    if gid:
        payload['bsdgrp_gid'] = gid

    if sudo:
        payload['bsdgrp_sudo'] = sudo

    return payload

def build_user_payload (name, uid, group_oid, creategroup, gecos, home, mode,
                    shell, email, password, pw_disabled, locked,
                    authorized_keys, sudo):

    if not name or len(name) == 0:
        update_module_msg("Can not create a payload: name is not defined")
        return FAILURE

    payload = { 'bsdusr_username' : name }

    if uid:
        payload['bsdusr_uid'] = uid

    if group_oid and not creategroup:
        payload['bsdusr_group'] = group_oid

    if creategroup:
        payload['bsdusr_creategroup'] = 'True'
    else:
        payload['bsdusr_creategroup'] = 'False'

    if gecos:
        payload['bsdusr_full_name'] = gecos

    if home:
        payload['bsdusr_home'] = home

    if mode:
        payload['bsdusr_mode'] = mode

    if shell:
        payload['bsdusr_shell'] = shell

    if email:
        payload['bsdusr_email'] = email

    if password:
        payload['bsdusr_password'] = password

    if pw_disabled:
        payload['bsdusr_password_disabled'] = 'True'
    else:
        payload['bsdusr_password_disabled'] = 'False'

    if locked:
        payload['bsdusr_locked'] = 'True'
    else:
        payload['bsdusr_locked'] = 'False'

    if authorized_keys:
        payload['bsdusr_sshpubkey'] = authorized_keys

    if sudo:
        payload['bsdusr_sudo'] = 'True'
    else:
        payload['bsdusr_sudo'] = 'False'

    return payload

def create_group (name, gid=None, sudo=False):
    if not name or len(name) == 0:
        update_module_msg("create_group(): name is missing")
        return FAILURE

    if group_exists(name):
        update_module_msg("Group '" + name + "' already exists")
        return OK

    payload = build_group_payload(name, gid)

    if not payload:
        update_module_msg("Can not create a group payload - please investigate")

    try:
        response = requests.post(
          api_groups_url,
          auth=(api_user, api_user_password),
          headers={'Content-Type': 'application/json'},
          verify=False,
          data=json.dumps(payload)
        )
        response.raise_for_status()
    except:
        update_module_msg("create_group(): something went wrong during POST API call. Response body: " + response.text)
        return FAILURE

    data = json.loads(response.text)

    return data["id"]

def update_group (name, gid, sudo=False):
    if not name or len(name) == 0:
        update_module_msg("update_group(): name is missing")
        return FAILURE

    if not group_exists(name):
        update_module_msg("update_group(): can not update what is not existing")
        return FAILURE

    group_oid = -1

    group_oid = get_group_oid(name)

    if not group_oid or group_oid == -1:
        update_module_msg("update_group(): can not retrieve group object id - please ivestigate")
        return FAILURE

    payload = build_group_payload(name, gid)

    if not payload:
        update_module_msg("update_group(): can not create a group payload - please investigate")

    try:
        response = requests.put(
          api_groups_url + str(group_oid) + "/",
          auth=(api_user, api_user_password),
          headers={'Content-Type': 'application/json'},
          verify=False,
          data=json.dumps(payload)
        )
        response.raise_for_status()
    except:
        update_module_msg("update_group(): something went wrong during POST API call. Response body: " + response.text)
        return FAILURE

    return OK

def create_user (username, uid, group, creategroup, gecos, home, mode,
                    shell, email, password, pw_disabled, locked,
                    authorized_keys, sudo):
    if user_exists(username):
        update_module_msg("User " + username + " already exists")
        return OK

    g_name = None

    if creategroup:
        if not group or len(group) == 0:
            g_name = username
        else:
            g_name = group
    else:
        if not creategroup and (not group or len(group) == 0):
            update_module_msg("create_user(): Either creategroup or group should be specified")
            return FAILURE

        g_name = group

    group_oid = -1

    # CHECK MUST BE IMPROVED IN ORDER TO VERIFY GIDs
    if group_exists(g_name):
        group_oid = get_group_oid(g_name)
    else:
        group_oid = create_group(g_name, uid)

    if not group_oid or group_oid == -1:
        update_module_msg("Can not derive group OID while creating a user -> please ivestigate. To whom it may concern: winbind cache can be involved")
        return FAILURE

    cg = False  # creategroup doesn't create primary groups with the same GID as users' UID, so has
                # to workaround the code

    payload = build_user_payload(username, uid, group_oid, cg, gecos, home, mode,
                        shell, email, password, pw_disabled, locked,
                        authorized_keys, sudo)

    if not payload:
        update_module_msg("create_user(): failure while creating a payload")
        return FAILURE

    try:
        response = requests.post(
          api_users_url,
          auth=(api_user, api_user_password),
          headers={'Content-Type': 'application/json'},
          verify=False,
          data=json.dumps(payload)
        )
        response.raise_for_status()
    except:
        update_module_msg("Something went wrong with the user creation API call. Response body: " + response.text)
        return FAILURE

    return OK

def update_user(username, uid, group, creategroup, gecos, home, mode,
                    shell, email, password, pw_disabled, locked,
                    authorized_keys, sudo):
    if not username or len(username) == 0:
        update_module_msg("update_user(): user name should be defined")
        return FAILURE

    if not user_exists(username):
        update_module_msg("update_user(): something went wrong, as you try to update but user hasn't been created yet")
        return FAILURE

    ul = get_user_list()

    _id = -1

    for user in ul:
        if user["bsdusr_username"] == username:
            _id = user["id"]
            break

    if _id == -1:
        update_module_msg("update_user(): could not find an ID of the user -- please investigate")
        return FAILURE

    g_name = None

    if creategroup:
        if not group or len(group) == 0:
            g_name = username
        else:
            g_name = group
    else:
        if not creategroup and (not group or len(group) == 0):
            update_module_msg("create_user(): Either creategroup or group should be specified")
            return FAILURE

        g_name = group

    group_oid = -1

    # CHECK MUST BE IMPROVED IN ORDER TO VERIFY GIDs
    if group_exists(g_name):
        group_oid = get_group_oid(g_name)
    else:
        group_oid = create_group(g_name, uid)

    if not group_oid or group_oid == -1:
        update_module_msg("update_user(): can not derive group OID while creating a user -> please ivestigate. To whom it may concern: winbind cache can be involved")
        return FAILURE

    cg = False  # creategroup doesn't create primary groups with the same GID
                # as users' UID, so has to workaround the code

    payload = build_user_payload(username, uid, group_oid, cg, gecos, home, mode,
                    shell, email, password, pw_disabled, locked,
                    authorized_keys, sudo)

    update_url = api_users_url + str(_id) + "/"
    
    try:
        response = requests.put(
                    update_url,
                    auth=(api_user, api_user_password),
                    headers={'Content-Type': 'application/json'},
                    verify=False,
                    data=json.dumps(payload))
        response.raise_for_status()
    except:
        update_module_msg("update_user(): something is wrong with the API call. Response body: " + response.text)
        return FAILURE

    return OK

def delete_user(name, rmgroup):
    if not user_exists(name):
        return OK

    ul = get_user_list()

    _id = -1
    _g_id = -1

    for user in ul:
        if user["bsdusr_username"] == name:
            _id = user["id"]
            _g_id = user["bsdusr_group"]
            break

    if _id == -1:
        update_module_msg("Could not find an ID of the user -- please investigate")
        return FAILURE


    if not api_delete_user(_id):
        update_module_msg("API DELETE call for user '" + name + "' failed")
        return FAILURE

    if rmgroup:
        g = get_group_data(_g_id)

        if g["bsdgrp_group"] != name:
            update_module_msg("In order do delete primary group of the user, names should be equal")
            return FAILURE

        if not api_delete_group(_g_id):
            update_module_msg("API DELETE call for group " + str(_g_id) + " failed")
            return FAILURE

    try:
        rc = subprocess.call("/usr/sbin/pw userdel " + name + " -r", shell=True)
    except OSError as e:
        print("Execution failed:", e, file=sys.stderr)

    if rc != os.EX_OK:
        update_module_msg("Final user cleanup failed - " + str(rc))
        return FAILURE

    return OK

def main():
    global msg
    global changed
    global api_user
    global api_user_password

    module = AnsibleModule(
        argument_spec = dict(
            api_user = dict(default='root', type='str'),
            api_pwd_file = dict(required=True, default=None, type='str'),
            state = dict(default='present', choices=['present', 'absent'], type='str'),
            username = dict(default=None, type='str'),
            uid = dict(default=None, type='int'),
            gid = dict(default=None, type='int'),
            group = dict(default=None, type='str'),
            creategroup = dict(default=True, type='bool'),
            gecos = dict(default=None, type='str'),
            home = dict(default=None, type='path'),
            mode = dict(default=None, type='str'),
            shell = dict(default='/usr/sbin/nologin', type='str'),
            email = dict(default=None, type='str'),
            password = dict(default=None, type='str', no_log=True),
            pw_disabled = dict(default=False, type='bool'),
            locked = dict(default=False, type='bool'),
            authorized_keys = dict(default=None, type='str'),
            sudo = dict(default=False, type='bool'),
            rmgroup = dict(default=None, type='bool'),
        ),
        supports_check_mode=True
    )

    if not is_freenas():
        module.fail_json(msg="The freenas_user module is only available on FreeNAS appliances")

    api_user = module.params.get('api_user')
    api_pwd_file = module.params.get('api_pwd_file')
    state = module.params.get('state')
    username = module.params.get('username')
    uid = module.params.get('uid')
    gid = module.params.get('gid')
    group = module.params.get('group')
    creategroup = module.params.get('creategroup')
    gecos = module.params.get('gecos')
    home = module.params.get('home')
    mode = module.params.get('mode')
    shell = module.params.get('shell')
    email = module.params.get('email')
    password = module.params.get('password')
    pw_disabled = module.params.get('pw_disabled')
    locked = module.params.get('locked')
    authorized_keys = module.params.get('authorized_keys')
    sudo = module.params.get('sudo')
    rmgroup = module.params.get('rmgroup')

    if not username and not group:
        module.fail_json(msg="Either username or group name should be defined in order to use this module")

    if not set_api_urls():
        module.fail_json(msg = msg)

    api_user_password = read_api_pwd(api_pwd_file)

    if not api_user_password or len(api_user_password) == 0:
        module.fail_json(msg="main(): can not access API user password file or file is empty")

    if username:
        if not user_exists(username) and state == "absent":
            module.exit_json(changed=False, msg="OK")
        elif not user_exists(username) and state == "present":
            res = create_user(username, uid, group, creategroup, gecos, home, mode,
                        shell, email, password, pw_disabled, locked,
                        authorized_keys, sudo)
            changed = True
        elif user_exists(username) and state == "present":
            res = update_user(username, uid, group, creategroup, gecos, home, mode,
                        shell, email, password, pw_disabled, locked,
                        authorized_keys, sudo)
        elif user_exists(username) and state == "absent":
            res = delete_user(username, rmgroup)
            changed = True
        else:
            module.fail_json(msg="Prohibited state of the module")
    elif group:
        if state == "present":
            if not group_exists(group) and gid:
                res = create_group(group, gid, sudo)
                changed = True
            elif group_exists(group) and (gid or sudo):
                res = update_group(group, gid, sudo)
            else:
                module.fail_json(msg="Prohibited state of the module")
        elif state == "absent":
            if not group_exists(group):
                module.exit_json(changed=False, msg="OK")
            else:
                res = delete_group(group)
                changed = True
    else:
        module.fail_json(msg="Prohibited state of the module")

    if not res:
        module.fail_json(msg=msg)

    if len(msg) == 0:
        msg = "OK"

    module.exit_json(changed=changed, msg=msg)

if __name__ == '__main__':
    main()
