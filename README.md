# log4j_interpreter
A Rust library for evaluating log4j substitution queries in order to determine whether or not malicious queries may exist.

This tool assumes any log line has already been decoded before being passed to the tool. For example, if the log line is URL encoded or base64 encoded when it's passed to this tool, it will by pass the tool. Only fully decoded log lines should be passed to the tool.