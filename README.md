# Bruteblock

Bruteblock allows system administrators to block various bruteforce attacks
on UNIX services. The program analyzes system logs and adds an attacker's IP
address into an ipfw2 table, effectively blocking them. Addresses are
automatically removed from the table after a specified amount of time.
Bruteblock uses regular expressions to parse logs, which gives flexibility
allowing it to be used with almost any network service. Bruteblock is written
in pure C, doesn't use any external programs and works with ipfw2 tables via
the raw sockets API.

## System requirements

Bruteblock requires FreeBSD with the ipfw2 firewall. To compile and run the
program you'll need the PCRE2 library, which may be installed from ports
(`devel/pcre2`).

## How it works

Bruteblock consists of two binaries: `bruteblock` and `bruteblockd`.

`bruteblock` is intended to be used in `/etc/syslog.conf` to pipe logs into.
It does log analysis and adds addresses into an ipfw2 table. Along with the
address and mask, every entry in an ipfw2 table has a `value` field, which is
used by bruteblock to store the expiration time as a 32-bit UNIX timestamp.

`bruteblockd` is a daemon which checks the ipfw2 table periodically and
removes expired entries.

Such a design avoids any IPC use and allows you to store entries for different
services in one table. It also makes it easy for the administrator to get a
list of currently blocked addresses and edit the list if needed.

## Installation

To compile the program run `make` in the bruteblock directory. After
compilation, copy the `bruteblock` and `bruteblockd` files into the system
binary directory (`/usr/local/sbin`). Copy the example configuration files
into the directory where configuration files are located
(`/usr/local/etc/bruteblock`) and edit them to suit your needs. Edit
`/etc/syslog.conf` and add the following entry:

```
auth.info;authpriv.info    | exec /usr/local/sbin/bruteblock -f /usr/local/etc/bruteblock/ssh.conf
```

then restart syslogd (`/etc/rc.d/syslogd restart`).

Run bruteblockd, specifying the same ipfw2 table number as in the config file
(with the `-t` parameter, e.g. `/usr/local/sbin/bruteblockd -t 1`). Finally,
add ipfw rules to block any packets from addresses that match the table, like
this:

```
ipfw add 100 deny ip from me to table\(1\)
ipfw add 100 deny ip from table\(1\) to me
```

Now bruteblock will do its job.

## Configuration

The configuration file for the bruteblock utility allows you to set the
following values:

- `regexp` - regular expression in Perl-compatible format that is used to
  extract failed password attempts from log files.
- `regexp0`, `regexp1`, ... `regexp9` - optional fields with up to 10
  additional regular expressions.
- `max_count`, `within_time` - define the time interval and the maximum number
  of failed password attempts during that interval. If the number is exceeded
  by a specific IP, that IP is blocked.
- `reset_ip` - time-to-live of a block. When it expires, the address is
  removed from the table, thus becoming unblocked.
- `ipfw2_table_no` - number of the ipfw2 table to add bad IPs to. Must match
  the `-t` parameter of bruteblockd.
- `ipv6_prefixlen` - prefix length used to aggregate IPv6 attackers (default
  `64`). IPv6 addresses are masked down to this network so that an attacker
  cannot evade blocking by rotating addresses inside its own prefix. Use `128`
  to block individual IPv6 addresses.

## TODO

Add configuration examples for other popular services, optimize the algorithms
used by bruteblock, add pf support.

## Feedback

Any feedback is appreciated. Author's email: samm [at] os2.kiev.ua.

## Homepage

<http://samm.kiev.ua/bruteblock/>
