//
//  JailbreakDetector.swift
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

import Foundation
import UIKit
import os.log

/// Configures the jailbreak detector.
public struct JailbreakDetectorConfiguration {

    /// Suspicious file paths.
    public var suspicousFilePaths: [String]

    /// Paths to files that exist outside the app sandbox.
    /// Used to verify that app sandboxing is intact.
    public var sandboxFilesPaths: [String]

    /// URL schemes that suspicous apps may respond to.
    public var suspiciousURLs: [String]

    /// A test string used to verify that app sandboxing is intact.
    public var sandboxTestString = "."

    /// If `true`, the jailbreak detector will halt immediately after encountering a failure.
    /// If `false`, the jailbreak detector will continue even after encountering a failure,
    /// and may potentially return multiple failure reasons when complete.
    public var haltAfterFailure = true

    /// If `true`, the jailbreak detector will log messages using `os.log`.
    public var loggingEnabled = false

    /// The log type.
    public var logType = OSLogType.info

    /// The default configuration.
    public static var `default`: JailbreakDetectorConfiguration {
        let filePaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/bin/ssh",
            "/usr/sbin/sshd",
            "/etc/apt"
        ]

        let sandboxFilesPaths = [
            "/private/jailbreak_detector.txt"
        ]

        let suspiciousURLs = [
            "cydia://package/com.example.package"
        ]

        return JailbreakDetectorConfiguration(suspicousFilePaths: filePaths,
                                              sandboxFilesPaths: sandboxFilesPaths,
                                              suspiciousURLs: suspiciousURLs)
    }
}

public class JailbreakDetector {

    /// A reason why the device is suspected to be jailbroken.
    public enum FailureReason: CustomStringConvertible {
        case suspiciousFileExists(filePath: String)
        case suspiciousFileIsReadable(filePath: String)
        case appSandbox(filePath: String)
        case suspiciousURLScheme(url: String)

        public var description: String {
            switch self {
            case .suspiciousFileExists(let filePath):
                return "Detected suspicious file at \(filePath)"
            case .suspiciousFileIsReadable(let filePath):
                return "Suspicious file can be opened at \(filePath)"
            case .appSandbox(let filePath):
                return "Able to write outside sandbox to \(filePath)"
            case .suspiciousURLScheme(let url):
                return "Can open suspicious URL scheme \(url)"
            }
        }
    }

    /// A detection result.
    public enum Result {
        case pass
        case fail(reasons: [FailureReason])
        case simulator
    }

    // MARK: - Properties

    // The log.
    let log = OSLog(subsystem: "com.github.conmulligan.JailbreakDetector", category: "Jailbreak Detection")

    /// The current configuration
    let configuration: JailbreakDetectorConfiguration

    // MARK: - Initialization

    public init(using configuration: JailbreakDetectorConfiguration = .default) {
        self.configuration = configuration
    }

    // MARK: - Detection

    /// Checks if the app is running on a device that may be jailbroken.
    /// - Returns: `true` if the app may be running on a jailbroken device. Otherwise, `false`.
    public func isJailbroken() -> Bool {
        switch detectJailbreak() {
        case .pass, .simulator:
            return false
        case .fail(reasons: _):
            return true
        }
    }

    /// Checks if the app is running on a device that may be jailbroken.
    /// - Returns: The detection result.
    public func detectJailbreak() -> Result {
        var result: Result

        #if !targetEnvironment(simulator)
        if configuration.loggingEnabled {
            os_log("Detected the iOS simulator.", log: log, type: configuration.logType)
        }
        //result = .simulator
        #endif

        var failureReasons = [FailureReason]()

        if let reasons = checkSuspiciousFilesExist() {
            failureReasons.append(contentsOf: reasons)
        }

        if let reasons = checkSuspiciousFilesReadable() {
            failureReasons.append(contentsOf: reasons)
        }

        if let reasons = checkAppSandbox() {
            failureReasons.append(contentsOf: reasons)
        }

        if failureReasons.isEmpty {
            if configuration.loggingEnabled {
                os_log("All checks passed!", log: log, type: configuration.logType)
            }
            result = .pass
        } else {
            result = .fail(reasons: failureReasons)
        }

        return result
    }
}

fileprivate extension JailbreakDetector {

    // MARK: - Jailbreak Checks

    /// Check for the presence of known suspicious files.
    /// - Returns: The failure reasons.
    private func checkSuspiciousFilesExist() -> [FailureReason]? {
        var reasons = [FailureReason]()

        for path in configuration.suspicousFilePaths {
            if FileManager.default.fileExists(atPath: path) {
                let reason = FailureReason.suspiciousFileExists(filePath: path)
                reasons.append(reason)

                if configuration.loggingEnabled {
                    os_log("Check failed: %s", log: log, type: configuration.logType, reason.description)
                }
            }
        }

        return reasons.isEmpty ? nil : reasons
    }

    /// Check for the presence of known suspicious files.
    /// - Returns: The failure reason.
    private func checkSuspiciousFilesReadable() -> [FailureReason]? {
        var reasons = [FailureReason]()

        for path in configuration.suspicousFilePaths {
            let file = fopen(path, "r")
            if file != nil {
                fclose(file)
                let reason = FailureReason.suspiciousFileIsReadable(filePath: path)
                reasons.append(reason)

                if configuration.loggingEnabled {
                    os_log("Check failed: %s", log: log, type: configuration.logType, reason.description)
                }
            }
        }

        return reasons.isEmpty ? nil : reasons
    }

    /// Check if the app can access files outside of its sandbox.
    /// - Returns: The failure reason.
    private func checkAppSandbox() -> [FailureReason]? {
        var reasons = [FailureReason]()

        do {
            for path in configuration.sandboxFilesPaths {
                try configuration.sandboxTestString.write(toFile: path, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: path)

                let reason = FailureReason.appSandbox(filePath: path)
                reasons.append(reason)

                if configuration.loggingEnabled {
                    os_log("Check failed: %s", log: log, type: configuration.logType, reason.description)
                }
            }
        } catch {
            // Ignore error.
        }

        return reasons.isEmpty ? nil : reasons
    }

    /// Check if the app can open suspicious URL schemes.
    /// - Returns: The failure reason.
    private func checkSuspiciousURLs() -> [FailureReason]? {
        var reasons = [FailureReason]()

        for path in configuration.suspiciousURLs {
            if let url = URL(string: path), UIApplication.shared.canOpenURL(url) {
                let reason = FailureReason.suspiciousURLScheme(url: path)
                reasons.append(reason)

                if configuration.loggingEnabled {
                    os_log("Check failed: %s", log: log, type: configuration.logType, reason.description)
                }
            }
        }

        return reasons.isEmpty ? nil : reasons
    }
}
