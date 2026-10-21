// Compile-only boundaries for the account adapter; never part of an app target.
import Foundation
import UIKit

enum BCDContentError: Error {
    case http(Int), tooLarge, refused(String)
}
struct BCDContentChunk {}

@MainActor enum BCDWebSignIn {
    static func topController() -> UIViewController? { nil }
}
