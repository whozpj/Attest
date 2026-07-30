import XCTest

/// Drives the real app in a real Simulator through XCTest's own touch-
/// injection protocol (testmanagerd) -- distinct from, and not blocked by,
/// macOS's Accessibility permission (which gates automating other Mac apps,
/// not automating the app under test inside the Simulator). This is the
/// native-iOS equivalent of driving the browser/PWA companion with
/// Playwright: a real UI, real taps, real network calls to the real server.
final class EnrollFlowUITests: XCTestCase {
    func testEnrolWithFaceID() throws {
        let app = XCUIApplication()
        app.launch()

        let enrolButton = app.buttons["enrolButton"]
        XCTAssertTrue(enrolButton.waitForExistence(timeout: 10), "enrolButton never appeared")

        let screenshotBeforeAttachment = XCTAttachment(screenshot: app.screenshot())
        screenshotBeforeAttachment.name = "0-before-tap"
        screenshotBeforeAttachment.lifetime = .keepAlways
        add(screenshotBeforeAttachment)

        enrolButton.tap()

        // The Face ID system sheet is presented by a separate system process
        // (not this app), and the actual "match" is simulated externally via
        // `xcrun simctl spawn <device> notifyutil -p ...` from the host side
        // (see ios/run-ui-proof.sh) while this test is waiting here -- there
        // is nothing for XCTest itself to tap for the biometric match itself,
        // only to wait for its result.
        let statusText = app.staticTexts["statusText"]
        let enrolled = NSPredicate(format: "label CONTAINS[c] %@", "enrolled")
        let failed = NSPredicate(format: "label CONTAINS[c] %@", "Failed")
        let enrolledExpectation = expectation(for: enrolled, evaluatedWith: statusText)
        let failedExpectation = expectation(for: failed, evaluatedWith: statusText)
        let result = XCTWaiter.wait(for: [enrolledExpectation, failedExpectation], timeout: 30)

        let screenshotAfterAttachment = XCTAttachment(screenshot: app.screenshot())
        screenshotAfterAttachment.name = "1-after-enrol-attempt"
        screenshotAfterAttachment.lifetime = .keepAlways
        add(screenshotAfterAttachment)

        XCTAssertEqual(result, .completed, "status text never resolved to enrolled or Failed within 30s — got: \(statusText.label)")
        XCTAssertEqual(statusText.label, "enrolled", "enrolment did not succeed")
    }
}
