# log4j_interpreter
A Rust library for evaluating log4j substitution queries in order to determine whether or not malicious queries may exist.

## Limitations

### Encoding

This tool assumes any log line has already been decoded before being passed to the tool. For example, if the log line is URL encoded or base64 encoded when it's passed to this tool, it will by pass the tool. Only fully decoded log lines should be passed to the tool.

### Interpolation

This tool assumes it's operating on entire log lines at once. Should the processed lines be passed to additional log aggregators that interpolate values again, this tool does not capture cases where the interpolated values re-expose a vulnerability.

## Test Executable

This package includes a test executable to which test strings can be passed on the command line.

Here is an example detecting an obfuscated use of `jndi:`.

```
$ ./log4j_interpreter
Usage: ./log4j_interpreter [test string]
$ ./log4j_interpreter 'hello ${base64:JHtqbmRpOmxkYXA6ZXZpbC5wYXJ0eX0=}'
Substitued: hello jndi:ldap:evil.party
JNDI: true
ENV: false
Recursion Limit: false
```

Here is an example that allows a benign string to pass:

```
$ ./log4j_interpreter 'a benign string ${base64:d2l0aCBzb21lIGJhc2U2NA==}'
Substitued: a benign string with some base64
JNDI: false
ENV: false
Recursion Limit: false
```
