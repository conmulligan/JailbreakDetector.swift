import XCTest
@testable import JailbreakDetector

final class JailbreakDetectorTests: XCTestCase {
    func testExample() {
        XCTAssertEqual(JailbreakDetector().configuration.sandboxTestString, ".")
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
