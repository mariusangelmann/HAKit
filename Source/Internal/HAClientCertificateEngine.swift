import Foundation
import Starscream

/// WebSocket engine that supports mTLS client certificate authentication.
///
/// Use this engine when connecting to a Home Assistant instance behind a proxy
/// that requires client certificate authentication (e.g., Cloudflare Access, nginx with mTLS).
///
/// Example usage:
/// ```swift
/// let identity: SecIdentity = // load from keychain
/// let engine = HAClientCertificateEngine(clientIdentity: identity)
/// let connectionInfo = try HAConnectionInfo(url: serverURL, engine: engine)
/// ```
@available(iOS 13.0, watchOS 6.0, tvOS 13.0, macOS 10.15, *)
public final class HAClientCertificateEngine: NSObject, Engine {
    private var task: URLSessionWebSocketTask?
    private var session: URLSession?
    private weak var delegate: EngineDelegate?

    private let clientIdentity: SecIdentity?
    private let evaluateServerTrust: ((SecTrust) throws -> Void)?

    /// Create an engine for mTLS client certificate authentication.
    ///
    /// - Parameters:
    ///   - clientIdentity: The client identity from the keychain to use for authentication.
    ///                     Pass nil to skip client certificate auth but still use this engine.
    ///   - evaluateServerTrust: Optional closure to perform custom server trust evaluation.
    ///                          Throw an error to reject the connection.
    public init(
        clientIdentity: SecIdentity?,
        evaluateServerTrust: ((SecTrust) throws -> Void)? = nil
    ) {
        self.clientIdentity = clientIdentity
        self.evaluateServerTrust = evaluateServerTrust
        super.init()
    }

    public func register(delegate: EngineDelegate) {
        self.delegate = delegate
    }

    public func start(request: URLRequest) {
        if session == nil {
            session = URLSession(configuration: .default, delegate: self, delegateQueue: nil)
        }
        task = session?.webSocketTask(with: request)
        doRead()
        task?.resume()
    }

    public func stop(closeCode: UInt16) {
        let closeCode = URLSessionWebSocketTask.CloseCode(rawValue: Int(closeCode)) ?? .normalClosure
        task?.cancel(with: closeCode, reason: nil)
    }

    public func forceStop() {
        stop(closeCode: UInt16(URLSessionWebSocketTask.CloseCode.abnormalClosure.rawValue))
    }

    public func write(string: String, completion: (() -> Void)?) {
        task?.send(.string(string)) { _ in
            completion?()
        }
    }

    public func write(data: Data, opcode: FrameOpCode, completion: (() -> Void)?) {
        switch opcode {
        case .binaryFrame:
            task?.send(.data(data)) { _ in
                completion?()
            }
        case .textFrame:
            if let text = String(data: data, encoding: .utf8) {
                write(string: text, completion: completion)
            }
        case .ping:
            task?.sendPing { _ in
                completion?()
            }
        default:
            break
        }
    }

    private func doRead() {
        task?.receive { [weak self] result in
            switch result {
            case .success(let message):
                switch message {
                case .string(let string):
                    self?.broadcast(event: .text(string))
                case .data(let data):
                    self?.broadcast(event: .binary(data))
                @unknown default:
                    break
                }
            case .failure(let error):
                self?.broadcast(event: .error(error))
                return
            }
            self?.doRead()
        }
    }

    private func broadcast(event: WebSocketEvent) {
        delegate?.didReceive(event: event)
    }
}

@available(iOS 13.0, watchOS 6.0, tvOS 13.0, macOS 10.15, *)
extension HAClientCertificateEngine: URLSessionWebSocketDelegate {
    public func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didOpenWithProtocol proto: String?
    ) {
        broadcast(event: .connected(["Sec-WebSocket-Protocol": proto ?? ""]))
    }

    public func urlSession(
        _ session: URLSession,
        webSocketTask: URLSessionWebSocketTask,
        didCloseWith closeCode: URLSessionWebSocketTask.CloseCode,
        reason: Data?
    ) {
        var reasonString = ""
        if let data = reason {
            reasonString = String(data: data, encoding: .utf8) ?? ""
        }
        broadcast(event: .disconnected(reasonString, UInt16(closeCode.rawValue)))
    }

    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        broadcast(event: .error(error))
    }
}

@available(iOS 13.0, watchOS 6.0, tvOS 13.0, macOS 10.15, *)
extension HAClientCertificateEngine: URLSessionDelegate {
    public func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        switch challenge.protectionSpace.authenticationMethod {
        case NSURLAuthenticationMethodClientCertificate:
            if let identity = clientIdentity {
                let credential = URLCredential(
                    identity: identity,
                    certificates: nil,
                    persistence: .forSession
                )
                completionHandler(.useCredential, credential)
            } else {
                completionHandler(.performDefaultHandling, nil)
            }

        case NSURLAuthenticationMethodServerTrust:
            guard let serverTrust = challenge.protectionSpace.serverTrust else {
                completionHandler(.performDefaultHandling, nil)
                return
            }

            if let evaluate = evaluateServerTrust {
                do {
                    try evaluate(serverTrust)
                    completionHandler(.useCredential, URLCredential(trust: serverTrust))
                } catch {
                    completionHandler(.cancelAuthenticationChallenge, nil)
                }
            } else {
                completionHandler(.performDefaultHandling, nil)
            }

        default:
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
