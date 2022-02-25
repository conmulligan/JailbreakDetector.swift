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
import OSLog

/// Configures the jailbreak detector.
public struct JailbreakDetectorConfiguration {
    /// Suspicious file paths.
    public var suspiciousFilePaths: [String]

    /// Paths to files that exist outside the app sandbox.
    /// Used to verify that app sandboxing is intact.
    public var sandboxFilePaths: [String]

    /// URL schemes that suspicious apps may respond to.
    public var suspiciousURLs: [String]

    /// A test string used to verify that app sandboxing is intact.
    public var sandboxTestString = "."

    /// If `true`, the jailbreak detector will halt immediately after encountering a failure.
    /// If `false`, the jailbreak detector will continue even after encountering a failure,
    /// and potentially return multiple failure reasons when complete.
    public var haltAfterFailure = true

    /// If `true`, the jailbreak detector will log messages using `os.log`.
    public var loggingEnabled = false

    /// The log type to use when writing log messages.
    public var logType = OSLogType.info

    /// The default configuration. In most cases you'll want to use this as-is
    /// or as a baseline instead of initializing your own configuration from scratch.
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

        return JailbreakDetectorConfiguration(suspiciousFilePaths: filePaths,
                                              sandboxFilePaths: sandboxFilesPaths,
                                              suspiciousURLs: suspiciousURLs)
    }
    
    // MARK: - Initialization
    
    /// Initialize a new configuration.
    /// - Parameters:
    ///   - suspiciousFilePaths: Suspicious file paths to check.
    ///   - sandboxFilePaths: Sandboxed file paths to check.
    ///   - suspiciousURLs: Suspicious URLs to check.
    public init(suspiciousFilePaths: [String]? = nil, sandboxFilePaths: [String]? = nil, suspiciousURLs: [String]? = nil) {
        self.suspiciousFilePaths = suspiciousFilePaths ?? [String]()
        self.sandboxFilePaths = sandboxFilePaths ?? [String]()
        self.suspiciousURLs = suspiciousURLs ?? [String]()
    }
}

/// The jailbreak detector.
///
/// For basic usage, create a `JailbreakDetector` instance and invoke the  `isJailbroken()` method:
///
/// ```
/// let detector = JailbreakDetector()
/// if detector.isJailbroken() {
///     // print("This device might be jailbroken!")
/// }
/// ```
///
/// If you need to dig deeper into the jailbreak detector results, use the `detectJailbreak()` method, which returns a `Result` enumeration:
///
/// ```
/// let detector = JailbreakDetector()
/// switch detector.detectJailbreak() {
/// case .pass:
///     print("Not jailbroken!")
/// case .fail(let reasons):
///     print("Might be jailbroken because:")
///     for reason in reasons {
///         print("Reason: \(reason)")
///     }
/// case .simulator:
///     print("Running in the simulator!")
/// }
/// ```
///
/// For finer control over the jailbreak detector's behaviour, use `JailbreakDetectorConfiguration`.
/// Note: in most cases you'll want to use the default configuration as-is or as a baseline instead of initializing your own configuration from scratch.
///
/// ```
/// // Start with the default configuration.
/// var configuration = JailbreakDetectorConfiguration.default
///
/// // Enable logging.
/// configuration.loggingEnabled = true
///
/// // Disable halt after failure. When disabled, the jailbreak detector will continue with its checks
/// // even after encountering a failure, and the `Result.fail` case may include multiple failure reasons.
/// configuration.haltAfterFailure = false
///
/// // Initialize the jailbreak detector with the custom configuration.
/// let detector = JailbreakDetector(using: configuration)
/// ````
public class JailbreakDetector {

    /// A reason why the device is suspected to be jailbroken.
    public enum FailureReason: CustomStringConvertible {
        /// A suspicious file exists on the filesystem.
        case suspiciousFileExists(filePath: String)

        /// A suspicious file is readable using `fopen`.
        case suspiciousFileIsReadable(filePath: String)

        /// Files are writable outside the app sandbox.
        case appSandbox(filePath: String)

        /// The application can open a URL with a suspicious URL scheme.
        case suspiciousURLScheme(url: String)

        /// Failure reason description.
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

    /// A jailbreak detection result.
    public enum Result {
        /// All jailbreak detector checks have passed.
        case pass

        /// The jailbreak detector has determined that the device is jailbroken
        /// for the given reasons. Note: if `haltAfterFailure` is enabled
        /// in the jailbreak configuration, only one failure reason will be supplied.
        case fail(reasons: [FailureReason])

        /// The app is running on the iOS Simulator.
        case simulator
    }

    // MARK: - Properties

    /// The current configuration.
    let configuration: JailbreakDetectorConfiguration

    /// The log used when writing log messages.
    private let log = OSLog(subsystem: "com.github.conmulligan.JailbreakDetector", category: "Jailbreak Detection")

    // MARK: - Initialization
    
    /// Initialize a new jailbreak detector with the supplied configuration.
    /// - Parameter configuration: The jailbreak detector configuration.
    public init(using configuration: JailbreakDetectorConfiguration = .default) {
        self.configuration = configuration
    }

    // MARK: - Detection

    /// Check if the app is running on a device that may be jailbroken.
    /// - Returns: `true` if the app may be running on a jailbroken device. Otherwise, `false`.
    public func isJailbroken() -> Bool {
        switch detectJailbreak() {
        case .pass, .simulator:
            return false
        case .fail:
            return true
        }
    }

    /// Check if the app is running on a device that may be jailbroken.
    /// - Returns: The detection result.
    public func detectJailbreak() -> Result {
        var result: Result

#if targetEnvironment(simulator)
        if configuration.loggingEnabled {
            os_log("Detected the iOS Simulator.", log: log, type: configuration.logType)
        }
        result = .simulator
#else
        var failureReasons = [FailureReason]()

        if let reasons = checkSuspiciousFiles() {
            failureReasons.append(contentsOf: reasons)
            if configuration.haltAfterFailure {
                return .fail(reasons: failureReasons)
            }
        }

        if let reasons = checkAppSandbox() {
            failureReasons.append(contentsOf: reasons)
            if configuration.haltAfterFailure {
                return .fail(reasons: failureReasons)
            }
        }

        if let reasons = checkSuspiciousURLs() {
            failureReasons.append(contentsOf: reasons)
            if configuration.haltAfterFailure {
                return .fail(reasons: failureReasons)
            }
        }

        // If no failures have been detected, give the all clear.
        // Otherwise, return a fail result with the failure reasons.
        if failureReasons.isEmpty {
            if configuration.loggingEnabled {
                os_log("All jailbreak checks passed!", log: log, type: configuration.logType)
            }
            result = .pass
        } else {
            result = .fail(reasons: failureReasons)
        }
#endif

        return result
    }
}

fileprivate extension JailbreakDetector {

    // MARK: - Jailbreak Checks

    /// Check for the presence of known suspicious files.
    /// - Returns: The failure reasons.
    private func checkSuspiciousFiles() -> [FailureReason]? {
        var reasons = [FailureReason]()

        for path in configuration.suspiciousFilePaths {
            // Check if suspicious file exists.
            if FileManager.default.fileExists(atPath: path) {
                let reason = FailureReason.suspiciousFileExists(filePath: path)
                reasons.append(reason)

                if configuration.loggingEnabled {
                    os_log("Check failed: %s", log: log, type: configuration.logType, reason.description)
                }

                if configuration.haltAfterFailure {
                    return reasons
                }
            }

            // Check if suspicious file is readable.
            let file = fopen(path, "r")
            if file != nil {
                fclose(file)
                let reason = FailureReason.suspiciousFileIsReadable(filePath: path)
                reasons.append(reason)

                if configuration.loggingEnabled {
                    os_log("Check failed: %s", log: log, type: configuration.logType, reason.description)
                }

                if configuration.haltAfterFailure {
                    return reasons
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
            for path in configuration.sandboxFilePaths {
                try configuration.sandboxTestString.write(toFile: path, atomically: true, encoding: .utf8)
                try FileManager.default.removeItem(atPath: path)

                let reason = FailureReason.appSandbox(filePath: path)
                reasons.append(reason)

                if configuration.loggingEnabled {
                    os_log("Check failed: %s", log: log, type: configuration.logType, reason.description)
                }

                if configuration.haltAfterFailure {
                    return reasons
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

                if configuration.haltAfterFailure {
                    return reasons
                }
            }
        }

        return reasons.isEmpty ? nil : reasons
    }
}
