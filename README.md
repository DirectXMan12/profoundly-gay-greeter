# Greeter

The idea is `ssh i.am@profoundly.gay` to create an account.

You get given a token, which you can then use to create your accounts.

## TODO

- tests :-P

## Setup

### Files

- `/etc/user-emails` should be owned by `root:root` and drwxrwx---
  with ACLs for `i.am:wx`

- `/etc/signup-tokens` should be owned by `i.am:i.am` and be rw-------

- `/usr/local/bin/profoundly-gay-greeter` should be this file

  Don't add it to `/etc/shells` -- if it's not in `/etc/shells`,
  it's treated as a restricted shell, and so if any user tries to
  `su i.am --shell /bin/bash`, they'll get redirected to this program
  (if you put it in /etc/shells, users will be able to `su` into `i.am`
  which would be Bad™)

  * for extra security, add `auth required pam_succeed_if.so user != i.am`
    to `/etc/pam.d/su`

### sudoers

```shell
$ cat /etc/sudoers.d/80-greeter
# allow i.am to run useradd without any options
# allow i.am to remove itself from the ssh folder after setup
i.am ALL = NOPASSWD: /usr/sbin/adduser [a-z][a-z0-9-]*, /usr/bin/setfacl -x i.am -R /home/*/.ssh
```

### sshd

```shell
$ cat /etc/ssh/sshd_config
<snip>
Match User i.am
        AuthenticationMethods none
        PasswordAuthentication yes
        PermitEmptyPasswords yes
        X11Forwarding no
        AllowTcpForwarding no
        PermitTTY yes
        ForceCommand /usr/local/bin/profoundly-gay-greeter
# end of file
```

### user config

- no password (explicitly delete it)
- empty homedir (needed for sshd)
- shell as `/usr/local/bin/profoundly-gay-greeter`
