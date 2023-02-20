use script;

#[test]
fn test_GetSigOpCount() {
    let mut s1: CScript = CScript::new();
    assert_eq!(s1.GetSigOpCount(False), 0);
    assert_eq!(s1.GetSigOpCount(True), 0);
}