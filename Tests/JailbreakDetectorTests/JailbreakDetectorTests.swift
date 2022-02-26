import XCTest
@testable import JailbreakDetector

final class JailbreakDetectorTests: XCTestCase {
    
    /// All test cases.
    static var allTests = [
        ("testDefaultConfiguration", testDefaultConfiguration),
        ("testFailingConfiguration", testFailingConfiguration),
        ("testSuspiciousFiles", testSuspiciousFiles),
        ("testDetectSandboxWriteable", testDetectSandboxWriteable),
    ]
    
    // MARK: - Test Cases
    
    /// Tests that the jailbreak detector doesn't fail using the default configuration.
    func testDefaultConfiguration() {
        let configuration = JailbreakDetectorConfiguration.default
        let detector = JailbreakDetector(using: configuration)
        XCTAssertFalse(detector.isJailbroken())
    }
    
    /// Tests a default configuration that's expected to fail.
    func testFailingConfiguration() {
        // Configure the default configuration to halt after failure and not automatically pass the simulator.
        var configuration = JailbreakDetectorConfiguration.default
        configuration.haltAfterFailure = false
        configuration.automaticallyPassSimulator = false
        
        // Run the detector and ensure it returns the expected failure.
        let detector = JailbreakDetector(using: configuration)
        XCTAssertTrue(detector.isJailbroken())
    }
    
    /// Tests for suspicious files.
    func testSuspiciousFiles() throws {
        // Configure the detector to check for a suspicious file and to not automatically pass the simulator.
        var configuration = JailbreakDetectorConfiguration()
        configuration.suspiciousFilePaths = ["/bin/bash"]
        configuration.haltAfterFailure = false
        configuration.automaticallyPassSimulator = false
        
        // Run the detector and ensure it returns the expected failure.
        let detector = JailbreakDetector(using: configuration)
        XCTAssertTrue(detector.isJailbroken())
    }
    
    /// Test app sandbox.
    func testDetectSandboxWriteable() throws {
        // Create a temporary file.
        let temporaryURL = makeTemporaryFileURL()
        
        // Configure the detector to check the "sandbox" URL and to not automatically pass the simulator.
        var configuration = JailbreakDetectorConfiguration()
        configuration.sandboxFilePaths = [temporaryURL.path]
        configuration.haltAfterFailure = false
        configuration.automaticallyPassSimulator = false
        
        // Run the detector and ensure it returns the expected failure.
        let detector = JailbreakDetector(using: configuration)
        let result = detector.detectJailbreak()
        guard case .fail = result else {
            XCTFail("Test should fail.")
            return
        }
        
        // Verify that the file has removed.
        XCTAssertFalse(FileManager.default.fileExists(atPath: temporaryURL.path))
    }
}

extension JailbreakDetectorTests {
    
    // MARK: - Support
    
    /// Creates a URL for a temporary file on disk and registers a teardown block to
    /// remove the at that URL (if it exists) during test teardown.
    private func makeTemporaryFileURL() -> URL {
        // Create a URL for an unique file in the system's temp directory.
        let directory = NSTemporaryDirectory()
        let filename = UUID().uuidString
        let fileURL = URL(fileURLWithPath: directory).appendingPathComponent(filename)
        
        // Add a teardown block to delete the file at `fileURL`.
        addTeardownBlock {
            do {
                let fileManager = FileManager.default
                // Check that the file exists before attempting to delete it.
                if fileManager.fileExists(atPath: fileURL.path) {
                    // Perform the delete the file.
                    try fileManager.removeItem(at: fileURL)
                    // Verify that the file no longer exists after the deletion.
                    XCTAssertFalse(fileManager.fileExists(atPath: fileURL.path))
                }
            } catch {
                // Treat errors during file deletion as a test failure.
                XCTFail("Error deleting temporary file: \(error)")
            }
        }
        
        // Return the temporary file URL.
        return fileURL
    }
}
