# JailbreakDetector.swift

A super simple, configurable and (optionally) verbose jailbreak detector for iOS.

JailbreakDetector isn't designed to prevent apps from running on jailbroken devices, or even detect jailbreaks with 100% accuracy. Instead, it focuses on detecting some common signs of a jailbreak, allows you to interrogate the results to determine why a jailbreak a suspected, and 

## Getting Started

For basic usage, create a `JailbreakDetector` instance and invoke the  `isJailbroken()` method:

```Swift
import JailbreakDetector

let detector = JailbreakDetector()
if detector.isJailbroken() {
    print("This device might be jailbroken!")
}
```

If you need to dig deeper into the jailbreak detector results, use the `detectJailbreak()` method, which returns a `Result` enumeration:

```Swift
let detector = JailbreakDetector()
switch detector.detectJailbreak() {
case .pass:
    print("Not jailbroken!")
case .fail(let reasons):
    print("Might be jailbroken because:")
    for reason in reasons {
        print("Reason: \(reason)")
    }
case .simulator:
    print("Running in the simulator!")
}
```

For finer control over the jailbreak detector's behaviour, use `JailbreakDetectorConfiguration`.
Note: in most cases you'll want to use the default configuration as-is, or as a baseline, instead of initializing your own configuration from scratch.

```Swift
// Start with the default configuration.
var configuration = JailbreakDetectorConfiguration.default

// Enable logging.
configuration.loggingEnabled = true

// Disable halt after failure. When disabled, the jailbreak detector will
// continue with its checks even after encountering a failure,
// and the `Result.fail` case may include multiple failure reasons.
configuration.haltAfterFailure = false

// Initialize the jailbreak detector with the custom configuration.
let detector = JailbreakDetector(using: configuration)
````

## Installation

JailbreakDetector is available through the [Swift Package Manager](https://swift.org/package-manager/). To use JailbreakDetector with SPM, add `https://github.com/conmulligan/JailbreakDetector.swift.git` as a dependency.

## License

JailbreakDetector is available under the MIT license. See the LICENSE file for more info.
