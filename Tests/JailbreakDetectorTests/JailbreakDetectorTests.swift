//
//  JailbreakDetectorTests.swift
//  JailbreakDetector
//
//  Created by Conor Mulligan on 19/02/2021.
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.

import XCTest
@testable import JailbreakDetector

final class JailbreakDetectorTests: XCTestCase {

    /// All test cases.
    static var allTests = [
        ("testDefaultConfiguration", testDefaultConfiguration),
        ("testDefaultConfigurationResult", testDefaultConfigurationResult),
        ("testFailingConfiguration", testFailingConfiguration),
        ("testSuspiciousFiles", testSuspiciousFiles),
        ("testDetectSandboxWriteable", testDetectSandboxWriteable)
    ]

    // MARK: - Test Cases

    /// Tests that the jailbreak detector doesn't fail using the default configuration.
    func testDefaultConfiguration() {
        let configuration = JailbreakDetectorConfiguration.default
        let detector = JailbreakDetector(using: configuration)
        XCTAssertFalse(detector.isJailbroken())
    }

    /// Tests the `Result` enumeration using the default configuration.
    func testDefaultConfigurationResult() {
        let configuration = JailbreakDetectorConfiguration.default
        let detector = JailbreakDetector(using: configuration)
        switch detector.detectJailbreak() {
        case .pass, .simulator, .macCatalyst:
            break
        case .fail:
            XCTFail("Jailbreak detected!")
        }
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
