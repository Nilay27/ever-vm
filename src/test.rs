use ton_types::{SliceData, Cell};
use crate::executor::Engine;
use crate::stack::{savelist::SaveList, StackItem};

static DEFAULT_CAPABILITIES: u64 = 0x572e;

fn read_boc(filename: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut file = std::fs::File::open(filename).unwrap();
    std::io::Read::read_to_end(&mut file, &mut bytes).unwrap();
    bytes
}

fn load_boc(filename: &str) -> Cell {
    let bytes = read_boc(filename);
    ton_types::read_single_root_boc(bytes).unwrap()
}

// Extracted params creation into a separate function
fn get_test_params() -> Vec<StackItem> {
    vec!(
        StackItem::int(0x76ef1ea),
        StackItem::int(0),
        StackItem::int(0),
        StackItem::int(0),
        StackItem::int(0),
        StackItem::int(0),
        StackItem::int(0),
        StackItem::tuple(vec!(
            StackItem::int(1000000000),
            StackItem::None
        )),
        StackItem::default(),
        StackItem::None,
        StackItem::None,
        StackItem::int(0),
    )
}

mod p256_chksigns_tests {
    use super::*;
    const P256_CHKSIGNS_BASE_PATH: &str = "asset/P256_CHKSIGNS/";

    fn get_boc_path(filename: &str) -> String {
        format!("{}{}", P256_CHKSIGNS_BASE_PATH, filename)
    }

    #[test]
    fn invalid_public_key(){
        //  When the passed in public key is not a point on the p256 curve
        let code = load_boc(&get_boc_path("InvalidPublicKey.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        let result = engine.execute();
        assert!(matches!(result, Err(e) if format!("{}", e).contains("cannot decode public key into EcPoint")));
    }

    #[test]
    fn invalid_signature_length(){
        //  signature length 66 bytes instead of 64
        let code = load_boc(&get_boc_path("InvalidSignatureLength.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        let result = engine.execute();
        assert!(matches!(result, Err(e) if format!("{}", e).contains("Invalid signature length")));
    }

    #[test]
    fn signature_underflow(){
        //  When the passed in public key is not a point on the p256 curve
        let code = load_boc(&get_boc_path("SignatureUnderflow.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        // engine.execute().unwrap();
        let result = engine.execute();
        assert!(matches!(result, Err(ref e) if e.to_string().contains("cell underflow")));
    }

    #[test]
    fn invalid_message_type(){
        //  P256_CHKSIGNS expects message to be a slice, so it should fail when it is not (for example int)
        let code = load_boc(&get_boc_path("InvalidMessageType.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        // engine.execute().unwrap();
        let result = engine.execute();
        assert!(matches!(result, Err(ref e) if e.to_string().contains("is not a slice")));
    }
    
    #[cfg(not(feature = "signature_no_check"))]
    #[test]
    fn invalid_signature() {
        // The public key is a valid point on p256 curve, but does not correspond to the signature
        let code = load_boc(&get_boc_path("WrongPublicKey.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        engine.execute().unwrap();
        let stack = engine.stack().get(0).as_bool().unwrap();
        assert_eq!(stack, false);
    }

    #[cfg(feature = "signature_no_check")]
    #[test]
    fn test_with_signature_no_check() {
        // Your test code here
        // The public key is a valid point on p256 curve, but does not correspond to the signature
        let code = load_boc(&get_boc_path("WrongPublicKey.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        engine.execute().unwrap();
        let stack = engine.stack().get(0).as_bool().unwrap();
        assert_eq!(stack, true);
    }

    #[cfg(not(feature = "signature_no_check"))]
    #[test]
    fn valid_signature() {
        let code = load_boc(&get_boc_path("ValidSignature.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        engine.execute().unwrap();
        let stack = engine.stack().get(0).as_bool().unwrap();
        assert_eq!(stack, true);
    }
}


mod p256_chksignu_tests {
    use super::*;

    const P256_CHKSIGNU_BASE_PATH: &str = "asset/P256_CHKSIGNU/";

    fn get_boc_path(filename: &str) -> String {
        format!("{}{}", P256_CHKSIGNU_BASE_PATH, filename)
    }

    #[test]
    fn invalid_public_key(){
        //  When the passed in public key is not a point on the p256 curve
        let code = load_boc(&get_boc_path("InvalidPublicKey.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        let result = engine.execute();
        assert!(matches!(result, Err(e) if format!("{}", e).contains("cannot decode public key into EcPoint")));
    }

    #[test]
    fn invalid_signature_length(){
        //  signature length 66 bytes instead of 64
        let code = load_boc(&get_boc_path("InvalidSignatureLength.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        let result = engine.execute();
        assert!(matches!(result, Err(e) if format!("{}", e).contains("Invalid signature length")));
    }

    #[test]
    fn signature_underflow(){
        //  When the passed in public key is not a point on the p256 curve
        let code = load_boc(&get_boc_path("SignatureUnderflow.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        // engine.execute().unwrap();
        let result = engine.execute();
        assert!(matches!(result, Err(ref e) if e.to_string().contains("cell underflow")));
    }

    #[test]
    fn invalid_message_type(){
        //  P256_CHKSIGNU expects message to be a integer, so it should fail when it is not (for example slice)
        let code = load_boc(&get_boc_path("InvalidMessageType.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        // engine.execute().unwrap();
        let result = engine.execute();
        assert!(matches!(result, Err(ref e) if e.to_string().contains("item is not an integer")));
    }
    
    #[cfg(not(feature = "signature_no_check"))]
    #[test]
    fn invalid_signature() {
        // The public key is a valid point on p256 curve, but does not correspond to the signature
        let code = load_boc(&get_boc_path("WrongPublicKey.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        engine.execute().unwrap();
        let stack = engine.stack().get(0).as_bool().unwrap();
        assert_eq!(stack, false);
    }

    #[cfg(feature = "signature_no_check")]
    #[test]
    fn test_with_signature_no_check() {
        // Your test code here
        // The public key is a valid point on p256 curve, but does not correspond to the signature
        let code = load_boc(&get_boc_path("WrongPublicKey.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        engine.execute().unwrap();
        let stack = engine.stack().get(0).as_bool().unwrap();
        assert_eq!(stack, true);
    }

    #[cfg(not(feature = "signature_no_check"))]
    #[test]
    fn valid_signature() {
        let code = load_boc(&get_boc_path("ValidSignature.boc"));
        let mut ctrls = SaveList::default();
        let params = get_test_params();
        ctrls.put(7, &mut StackItem::tuple(vec!(StackItem::tuple(params.clone())))).unwrap();

        let mut engine = Engine::with_capabilities(DEFAULT_CAPABILITIES).setup_with_libraries(
            SliceData::load_cell_ref(&code).unwrap(),
            Some(ctrls),
            None,
            None,
            vec!());
        engine.dump_ctrls(false);
        engine.execute().unwrap();
        let stack = engine.stack().get(0).as_bool().unwrap();
        assert_eq!(stack, true);
    }
}
