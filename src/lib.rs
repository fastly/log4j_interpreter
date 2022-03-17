//! This is an attempted rough-approximation of the logic used to perform
//! substitutions in Log4j, and supports recursive expansions. The logic is
//! based on the `StrSubstitutor.java` file from
//! [log4j-core](https://github.com/apache/logging-log4j2/blob/0043e9238af0efd9dbce462463e0fa1bf14e35b0/log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/StrSubstitutor.java#L928-L1070).
//!
//! The `parse()` function will run until a fixed point is reached, that is, it
//! will keep re-parsing until the input is the same as the output. This
//! prevents separate expansions from being able to reconstruct another
//! expansion that is then forwarded to other logging pipelines.
//!
//! I used a type-state approach for the parser so that I could lean on the
//! compiler to show me state transitions I missed.
//!
//! New substitutions should be added to the `subsitute()` function.

#[derive(Debug)]
pub struct Findings {
    handlers: Vec<Handler>,
    pub saw_jndi: bool,
    pub saw_env: bool,
    pub saw_main: bool,
    pub hit_recursion_limit: bool,
}

impl Findings {
    pub fn new() -> Self {
        Findings {
            handlers: Vec::new(),
            saw_jndi: false,
            saw_env: false,
            saw_main: false,
            hit_recursion_limit: false,
        }
    }

    pub fn merge(&mut self, mut new_findings: Findings) {
        self.saw_jndi |= new_findings.saw_jndi;
        self.saw_env |= new_findings.saw_env;
        self.saw_main |= new_findings.saw_main;
        self.hit_recursion_limit |= new_findings.hit_recursion_limit;
        self.handlers.extend(new_findings.handlers.drain(..));
    }
}

#[derive(Debug)]
enum State<'i> {
    Plain(Plain<'i>),
    Escape1(Escape1<'i>),
    Escape2(Escape2<'i>),
    Substitute(Substitute<'i>),
    SubstituteNest1(SubstituteNest1<'i>),
    DoSubstitute(DoSubstitute<'i>),
    Done(Vec<u8>),
}

impl<'i> State<'i> {
    fn new(input: &'i [u8], findings: &'i mut Findings, recursion_limit: usize) -> Self {
        Self::Plain(Plain {
            shared: Shared {
                recursion_limit,
                accumulated: Default::default(),
                rest: input.iter(),
                findings,
            },
        })
    }

    fn is_done(&self) -> bool {
        if let State::Done(_) = self {
            true
        } else {
            false
        }
    }

    fn step(self) -> Self {
        match self {
            State::Plain(t) => t.step(),
            State::Escape1(e) => e.step(),
            State::Escape2(e) => e.step(),
            State::Substitute(s) => s.step(),
            State::SubstituteNest1(s) => s.step(),
            State::DoSubstitute(s) => s.step(),
            d @ State::Done(_) => d,
        }
    }

    fn finish(self) -> Vec<u8> {
        if let State::Done(a) = self {
            a
        } else {
            panic!("Called finish() when not done.")
        }
    }
}

#[derive(Debug)]
struct Shared<'i> {
    recursion_limit: usize,
    accumulated: Vec<u8>,
    rest: std::slice::Iter<'i, u8>,
    findings: &'i mut Findings,
}

impl<'i> Shared<'i> {
    fn accumulated(self) -> Vec<u8> {
        self.accumulated
    }
}

#[derive(Debug)]
struct Plain<'i> {
    shared: Shared<'i>,
}

impl<'i> Plain<'i> {
    fn step(self) -> State<'i> {
        let Self { mut shared } = self;
        match shared.rest.next() {
            // When we see a '$', this may be the start of an escape of the
            // start sequence. This may also be the start of a substitution. To
            // find out, we start with the assumption this is an escape, and
            // allow the escape types to determine which of the paths we're
            // taking.
            Some(b'$') => State::Escape1(Escape1 { shared }),
            // Any other character we see gets accumulated.
            Some(c) => {
                shared.accumulated.push(*c);
                State::Plain(Plain { shared })
            }
            // If we're out of characters, then we're done!
            None => State::Done(shared.accumulated()),
        }
    }
}

#[derive(Debug)]
struct Escape1<'i> {
    shared: Shared<'i>,
}

impl<'i> Escape1<'i> {
    fn step(self) -> State<'i> {
        let Self { mut shared } = self;
        match shared.rest.next() {
            // We got here because we saw a '$'. If we see _another_ '$', then
            // we might actually be escaping the start sequence.
            Some(b'$') => {
                shared.accumulated.push(b'$');
                State::Escape2(Escape2 { shared })
            }
            // We got here because we saw a '$'. If we see a '{', then we're now
            // performing a substitution!
            Some(b'{') => State::Substitute(Substitute {
                shared,
                sub: Default::default(),
                nesting: 0,
            }),
            // If we don't see a '$' or a '{', the we are not escaping or
            // substituting. Push the '$' that got us here, and the character,
            // then go back to plain.
            Some(c) => {
                shared.accumulated.push(b'$');
                shared.accumulated.push(*c);
                State::Plain(Plain { shared })
            }
            None => {
                shared.accumulated.push(b'$');
                State::Done(shared.accumulated())
            }
        }
    }
}

#[derive(Debug)]
struct Escape2<'i> {
    shared: Shared<'i>,
}

impl<'i> Escape2<'i> {
    fn step(self) -> State<'i> {
        let Self { mut shared } = self;
        match shared.rest.next() {
            Some(b'{') => {
                shared.accumulated.push(b'{');
                State::Plain(Plain { shared })
            }
            Some(c) => {
                shared.accumulated.push(b'$');
                shared.accumulated.push(*c);
                State::Plain(Plain { shared })
            }
            None => {
                shared.accumulated.push(b'$');
                State::Done(shared.accumulated())
            }
        }
    }
}

#[derive(Debug)]
struct Substitute<'i> {
    shared: Shared<'i>,
    sub: Vec<u8>,
    nesting: usize,
}

impl<'i> Substitute<'i> {
    fn step(self) -> State<'i> {
        let Self {
            mut shared,
            mut sub,
            nesting,
        } = self;
        match shared.rest.next() {
            Some(b'$') => {
                sub.push(b'$');
                State::SubstituteNest1(SubstituteNest1 {
                    shared,
                    sub,
                    nesting,
                })
            }
            Some(b'}') => {
                if nesting == 0 {
                    State::DoSubstitute(DoSubstitute { shared, sub })
                } else {
                    sub.push(b'}');
                    State::Substitute(Substitute {
                        shared,
                        sub,
                        nesting: nesting - 1,
                    })
                }
            }
            Some(c) => {
                sub.push(*c);
                State::Substitute(Self {
                    shared,
                    sub,
                    nesting,
                })
            }
            None => {
                shared.accumulated.push(b'$');
                shared.accumulated.push(b'{');
                shared.accumulated.extend_from_slice(&sub);
                State::Done(shared.accumulated())
            }
        }
    }
}

#[derive(Debug)]
struct SubstituteNest1<'i> {
    shared: Shared<'i>,
    sub: Vec<u8>,
    nesting: usize,
}

impl<'i> SubstituteNest1<'i> {
    fn step(self) -> State<'i> {
        let Self {
            mut shared,
            mut sub,
            nesting,
        } = self;
        match shared.rest.next() {
            Some(b'{') => {
                sub.push(b'{');
                State::Substitute(Substitute {
                    shared,
                    sub,
                    nesting: nesting + 1,
                })
            }
            Some(b'}') => {
                // This handles the odd case where a '$' comes right before a
                // '}' such as in '${::-$}'.
                if nesting == 0 {
                    State::DoSubstitute(DoSubstitute { shared, sub })
                } else {
                    sub.push(b'}');
                    State::Substitute(Substitute {
                        shared,
                        sub,
                        nesting: nesting - 1,
                    })
                }
            }
            Some(c) => {
                sub.push(*c);
                State::Substitute(Substitute {
                    shared,
                    sub,
                    nesting,
                })
            }
            None => State::Done(shared.accumulated()),
        }
    }
}

#[derive(Debug)]
struct DoSubstitute<'i> {
    shared: Shared<'i>,
    sub: Vec<u8>,
}

impl<'i> DoSubstitute<'i> {
    fn step(self) -> State<'i> {
        let Self { mut shared, sub } = self;

        let (substituted, handler) = if shared.recursion_limit == 0 {
            shared.findings.hit_recursion_limit = true;
            ("ERROR_RECURSION_LIMIT_REACHED".into(), None)
        } else {
            let (parsed, new_findings) = parse(&sub, shared.recursion_limit - 1);
            shared.findings.merge(new_findings);
            substitute(&parsed)
        };

        shared.accumulated.extend_from_slice(&substituted);
        match handler {
            Some(Handler::Jndi) => {
                shared.findings.saw_jndi = true;
            }
            Some(Handler::Env) => {
                shared.findings.saw_env = true;
            }
            Some(Handler::Main) => {
                shared.findings.saw_main = true;
            }
            _ => { /* other handlers aren't interesting on their own */ }
        }

        State::Plain(Plain { shared })
    }
}

fn split_slice<'a, T: PartialEq>(input: &'a [T], delim: &'a [T]) -> (&'a [T], &'a [T]) {
    let mut before: &[T] = input;
    let mut after: &[T] = &[];
    for (ix, w) in input.windows(2).enumerate() {
        if delim == w {
            before = &input[0..ix];

            let default_ix = ix + delim.len();
            if input.len() >= default_ix {
                after = &input[default_ix..];
            }
            break;
        }
    }
    (before, after)
}

fn strip_lower_ascii_prefix<'a>(input: &'a [u8], prefix: &'a [u8]) -> Option<&'a [u8]> {
    // TODO: how to handle `input` consisting of unicode characters that may lowercase to
    // characteres matching `prefix`, but are not the same by ASCII case rules? eg `ı` -> `i`.
    // It might just be the case that unicode normalization doesn't apply here.

    if input.len() >= prefix.len() {
        if input[..prefix.len()].eq_ignore_ascii_case(prefix) {
            Some(&input[prefix.len()..])
        } else {
            None
        }
    } else {
        // cannot possibly match.
        None
    }
}

/// `${date:...}` expands a format string using the current time. The date
/// formatters use SimpleDateFormat
/// (https://docs.oracle.com/javase/6/docs/api/java/text/SimpleDateFormat.html).
///
/// A summary of the formatting rules is copied here:
///
/// > Date and time formats are specified by date and time pattern strings.
/// > Within date and time pattern strings, unquoted letters from 'A' to 'Z' and
/// > from 'a' to 'z' are interpreted as pattern letters representing the
/// > components of a date or time string. Text can be quoted using single
/// > quotes (') to avoid interpretation. "''" represents a single quote. All
/// > other characters are not interpreted; they're simply copied into the
/// > output string during formatting or matched against the input string during
/// > parsing.
///
/// We approximate this by copying quoted values literally into the output, and
/// replacing each formatting character with a space (rather than its actual
/// value).
fn substitute_date(input: &[u8]) -> Vec<u8> {
    let mut last_char = None;
    let mut quoted = false;
    let mut output = Vec::new();
    for b in input {
        match *b {
            b'\'' => {
                if last_char == Some(b'\'') {
                    // two single quotes in a row is a single quote
                    output.push(b'\'');
                    quoted = false;
                } else if quoted {
                    // we were already quoted. stop that.
                    quoted = false;
                } else {
                    // we're not currently quoted.
                    quoted = true;
                }
            }
            b'G' | b'y' | b'M' | b'w' | b'W' | b'D' | b'd' | b'F' | b'E' | b'a' | b'H' | b'k'
            | b'K' | b'h' | b'm' | b's' | b'S' | b'z' | b'Z' => {
                if quoted {
                    output.push(*b);
                } else {
                    output.push(b' ');
                }
            }
            other => {
                output.push(other);
            }
        }

        last_char = Some(*b);
    }

    output
}

fn substitute(input: &[u8]) -> (Vec<u8>, Option<Handler>) {
    const DEFAULT_DELIMITER: &[u8; 2] = b":-";
    let (value, default) = split_slice(input, DEFAULT_DELIMITER);

    if let Some(rest) = strip_lower_ascii_prefix(value, b"lower:") {
        if let Ok(s) = std::str::from_utf8(rest) {
            (s.to_lowercase().into(), Some(Handler::Lower))
        } else {
            ("ERROR_LOWER_INVALID_UTF8".into(), None)
        }
    } else if let Some(rest) = strip_lower_ascii_prefix(value, b"upper:") {
        if let Ok(s) = std::str::from_utf8(rest) {
            (s.to_uppercase().into(), Some(Handler::Upper))
        } else {
            ("ERROR_UPPER_INVALID_UTF8".into(), None)
        }
    } else if let Some(rest) = strip_lower_ascii_prefix(value, b"base64:") {
        if let Ok(d) = base64::decode(rest) {
            (d, Some(Handler::Base64))
        } else {
            ("ERROR_BASE64_DECODE_INVALID".into(), None)
        }
    } else if let Some(_) = strip_lower_ascii_prefix(value, b"jndi:") {
        (value.into(), Some(Handler::Jndi))
    } else if let Some(_) = strip_lower_ascii_prefix(value, b"env:") {
        // If default exists, we'll use it instead of `value`. If `default` is not defined, it's an
        // empty slice, which is what we'll use anyway.
        (default.into(), Some(Handler::Env))
    } else if let Some(_) = strip_lower_ascii_prefix(value, b"main:") {
        // We don't know arguments to the `main` function, but we assume attackers don't either.
        // So, assuming that there are no default `main` arguments that can be used to assume an
        // undesired expansion in a log4j string, either the expansion should result in a no-op, or
        // the expansion should leak a `main` argument.
        //
        // Report the `main` handler for the possible information disclosure risk, then assume
        // empty/default string expansion in case this was just obfuscatory.
        (default.into(), Some(Handler::Main))
    } else if let Some(date_fmt) = strip_lower_ascii_prefix(value, b"date:") {
        (substitute_date(date_fmt), Some(Handler::Date))
    } else {
        (default.into(), None)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Handler {
    Env,
    Jndi,
    Base64,
    Upper,
    Lower,
    Main,
    Date,
}

pub fn parse(input: &[u8], recursion_limit: usize) -> (Vec<u8>, Findings) {
    let mut input = input.to_owned();

    let mut findings = Findings::new();

    // This loop runs until we reach a FIXED POINT. That is, we run until the
    // input and the output are identical. When performing substitutions, it's
    // possible to have new strings created that could get forwarded to other
    // logging pipelines. By running until we reach a fixed point, we prevent
    // any leakage to further logging systems.
    loop {
        let mut s = State::new(&input, &mut findings, recursion_limit);

        loop {
            if s.is_done() {
                break;
            } else {
                s = s.step();
            }
        }

        let current = s.finish();

        if current == input {
            return (current, findings);
        } else {
            input = current;
        }
    }
}

pub fn parse_str(
    input: impl AsRef<str>,
    recursion_limit: usize,
) -> Result<(String, Findings), std::string::FromUtf8Error> {
    let (result, findings) = parse(input.as_ref().as_bytes(), recursion_limit);
    String::from_utf8(result).map(|s| (s, findings))
}
