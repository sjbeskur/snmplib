
extern crate snmplib;

use snmplib::SyncSession;

#[test]
fn it_works() {

    let session = SyncSession::new("192.168.88.1", "public".as_bytes(), Some(std::time::Duration::from_secs(2)), 0);

    assert_eq!(2 + 2, 4); // TODO add real tests
}
