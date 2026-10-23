// Synthetic protocol fixtures: no account credentials, game binaries or live CDN traffic.
import Foundation

private func be(_ value: Int, _ count: Int) -> Data { BCDBnetCASC.integer(UInt64(value), count, little: false) }
private func plainBLTE(_ body: Data) -> Data { Data("BLTE".utf8) + Data(repeating: 0, count: 4) + Data([78]) + body }
private func framedBLTE(_ body: Data) -> Data {
    let block = Data([78]) + body
    return Data("BLTE".utf8) + be(36, 4) + Data([15, 0, 0, 1]) + be(block.count, 4) + be(body.count, 4)
        + (try! BCDBnetNGDP.keyBytes(BCDBnetNGDP.md5(block))) + block
}
private func tagBytes() -> Data {
    var data = Data()
    for (name, kind, mask) in [("Windows", 1, 0x80), ("OSX", 1, 0x40), ("x86_64", 2, 0x80), ("arm64", 2, 0x40)] {
        data.append(Data(name.utf8)); data.append(0); data.append(be(kind, 2)); data.append(UInt8(mask))
    }
    return data
}
private func installFixture(path: String, content: String, size: Int) throws -> Data {
    var data = Data("IN".utf8) + Data([1, 16]) + be(4, 2) + be(2, 4) + tagBytes()
    for name in [path, "Mac.app/ignored"] {
        data.append(Data(name.utf8)); data.append(0); data.append(try BCDBnetNGDP.keyBytes(content)); data.append(be(size, 4))
    }
    return data
}

private final class FixtureProtocol: URLProtocol {
    static var files: [String: Data] = [:]
    static var ignoreRange = false
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let url = request.url, let body = Self.files[url.lastPathComponent] else {
            client?.urlProtocol(self, didFailWithError: URLError(.fileDoesNotExist)); return
        }
        var selected = body, headers = [String: String](), status = 200
        if let range = request.value(forHTTPHeaderField: "Range"), !Self.ignoreRange {
            let parts = range.dropFirst(6).split(separator: "-", omittingEmptySubsequences: false)
            let start = Int(parts[0])!, end = Int(parts[1]) ?? body.count - 1
            selected = body.subdata(in: start..<(end + 1))
            status = 206; headers["Content-Range"] = "bytes \(start)-\(end)/\(body.count)"
        }
        client?.urlProtocol(self, didReceive: HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: selected)
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
private final class FixtureSource: BCDChunkSource, @unchecked Sendable {
    let source: BCDBnetChunkSource
    let http = BCDHTTPStream(protocols: [FixtureProtocol.self])
    var count = 0
    init(_ build: BCDBnetBuild) { source = BCDBnetChunkSource(build) }
    deinit { http.close() }
    func urls(for chunk: BCDContentChunk) async throws -> [URL] { try await source.urls(for: chunk) }
    func refresh(group: String) async throws {}
    func fetch(_ chunk: BCDContentChunk, url: URL, into consumer: BCDHTTPConsumer, stream: BCDHTTPStream) async throws {
        count += 1
        try await source.fetch(chunk, url: url, into: consumer, stream: http)
    }
}

func runDownloadChecks() async throws {
    let body = Data("MZ synthetic fixture, never executed".utf8), raw = plainBLTE(body)
    let encoded = BCDBnetNGDP.md5(raw), content = BCDBnetNGDP.md5(body)
    try require(try BCDBnetBLTE.decode(raw, key: encoded, limit: body.count) == body, "decode single-frame BLTE")
    let framed = framedBLTE(body), framedKey = BCDBnetNGDP.md5(framed.prefix(36))
    try require(try BCDBnetBLTE.decode(framed, key: framedKey, limit: body.count) == body, "decode checked BLTE frames")
    let collector = BCDHTTPCollector(limit: framed.count)
    let verifier = BCDBnetVerifiedConsumer(target: collector, key: framedKey, size: Int64(framed.count))
    try verifier.begin(at: 0)
    for (i, byte) in framed.enumerated() {
        if i == 20 { try verifier.begin(at: 20) }
        try verifier.receive(Data([byte]))
    }
    try verifier.finish()
    require(collector.data == framed, "one-byte network fragments and a resumed stream preserve encoded data")
    var broken = framed; broken[broken.count - 1] ^= 1
    refuses("BLTE payload corruption refused") { _ = try BCDBnetBLTE.decode(broken, key: framedKey, limit: body.count) }
    refuses("BLTE output bound enforced") { _ = try BCDBnetBLTE.decode(framed, key: framedKey, limit: 2) }
    for cut in 0..<36 { refuses("truncated BLTE refused") { _ = try BCDBnetBLTE.decode(Data(framed.prefix(cut)), key: framedKey, limit: 100) } }
    let install = try installFixture(path: "WowClassic.exe", content: content, size: body.count)
    let entries = try BCDBnetNGDP.install(install, locale: "enUS")
    require(entries.count == 1 && entries[0].path == "WowClassic.exe", "install tags select Windows x64 only")
    refuses("selected manifest cannot escape installation") {
        _ = try BCDBnetNGDP.install(installFixture(path: "../escape.exe", content: content, size: 1), locale: "enUS")
    }
    var dl = Data("DL".utf8) + Data([3, 16, 0]) + be(2, 4) + be(4, 2) + Data([1, 0, 0, 0, 0])
    for _ in 0..<2 { dl.append(try BCDBnetNGDP.keyBytes(encoded)); dl.append(be(raw.count, 5)); dl.append(contentsOf: [0, 0]) }
    dl.append(tagBytes())
    try require(try BCDBnetNGDP.download(dl, locale: "enUS").count == 1, "DL v3 flags and alternative tags")
    var page = Data([1]) + be(body.count, 5) + (try BCDBnetNGDP.keyBytes(content)) + (try BCDBnetNGDP.keyBytes(encoded))
    page.append(Data(repeating: 0, count: 1024 - page.count))
    var en = Data("EN".utf8) + Data([1, 16, 16]) + be(1, 2) + be(1, 2) + be(1, 4) + be(1, 4) + Data([0]) + be(2, 4) + Data([78, 0])
    en.append(try BCDBnetNGDP.keyBytes(content)); en.append(try BCDBnetNGDP.keyBytes(BCDBnetNGDP.md5(page))); en.append(page)
    try require(try BCDBnetNGDP.encoding(en, wanted: [content])[content] == encoded, "content-to-encoding lookup with page hash")
    var badPage = en; badPage[badPage.count - 1] ^= 1
    refuses("corrupt encoding page refused") { _ = try BCDBnetNGDP.encoding(badPage, wanted: [content]) }
    let archiveKey = String(repeating: "a", count: 32)
    var index = try BCDBnetNGDP.keyBytes(encoded); index.append(be(raw.count, 4)); index.append(be(1234, 4))
    index.append(Data(repeating: 0, count: 1024 - index.count))
    var footer = Data(repeating: 0, count: 28)
    footer[8] = 1; footer[11] = 1; footer[12] = 4; footer[13] = 4; footer[14] = 16; footer[15] = 8; footer[16] = 1
    index.append(footer)
    let location = try BCDBnetNGDP.archive(index, archive: archiveKey, wanted: [encoded])[encoded]
    require(location?.offset == 1234 && location?.size == raw.count, "paged CDN archive range lookup")
    require(BCDBnetCASC.hash(Data()).0 == 0xdeadbeef, "lookup3 empty vector")

    FixtureProtocol.files = ["range": Data(0..<20)]
    let http = BCDHTTPStream(protocols: [FixtureProtocol.self]); defer { http.close() }
    let request = URLRequest(url: URL(string: "https://fixture.blizzard.com/range")!)
    let ranged = BCDHTTPCollector(limit: 3)
    try await http.fetch(request, into: ranged, range: 5..<8)
    require(ranged.data == Data([5, 6, 7]), "archive ranges use absolute wire and relative consumer offsets")
    FixtureProtocol.ignoreRange = true
    do { try await http.fetch(request, into: BCDHTTPCollector(limit: 100), range: 5..<8); fatalError("ignored range accepted") }
    catch BCDContentError.http(200) { print("PASS: server ignoring archive Range refused") }
    FixtureProtocol.ignoreRange = false

    let config = Data(("root = " + content + "\n").utf8), cdn = Data(("archives = " + archiveKey + "\n").utf8)
    var build = BCDBnetBuild(product: "wow_classic_era", region: "us", version: "1.15.9.1",
            build: BCDBnetNGDP.md5(config), cdn: BCDBnetNGDP.md5(cdn), path: "tpr/wow", hosts: ["fixture.blizzard.com"],
            locale: "enUS", buildConfig: config, cdnConfig: cdn,
            payloads: [.init(key: encoded, size: Int64(raw.count), archive: archiveKey, offset: 1234)], install: entries)
    build.install[0].encoded = encoded
    let plan = try BCDBnetDownload.plan(build)
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let stage = directory.appendingPathComponent("stage"), job = directory.appendingPathComponent("job")
    let source = FixtureSource(build)
    var options = BCDContentOptions(); options.streams = 1; options.backoff = 0; options.attempts = 1; options.freeSpace = { _ in 0 }
    do { try await BCDContentEngine.download(plan, stage: stage, jobFolder: job, source: source, options: options, progress: { _ in }); fatalError("space check skipped") }
    catch BCDContentError.notEnoughSpace { print("PASS: disk check precedes payload download") }
    FixtureProtocol.files = [archiveKey: Data(repeating: 0, count: 1234) + raw + Data([0, 0])]
    options.freeSpace = { _ in Int64.max / 2 }
    try await BCDContentEngine.download(plan, stage: stage, jobFolder: job, source: source, options: options, progress: { _ in })
    require(source.count == 1, "native source passes verified payload to shared queue engine")
    try await BCDContentEngine.download(plan, stage: stage, jobFolder: job, source: source, options: options, progress: { _ in })
    require(source.count == 1, "resume reuses journalled payload without network")
    let stagedPayload = stage.appendingPathComponent("payload/" + encoded.prefix(2) + "/" + encoded)
    var damaged = raw; damaged[damaged.count - 1] ^= 1
    try damaged.write(to: stagedPayload)
    refuses("assembly refuses a damaged journalled payload") { _ = try BCDBnetCASC.assemble(build, stage: stage) }
    try raw.write(to: stagedPayload)
    let output = try BCDBnetCASC.assemble(build, stage: stage)
    require(BCDBnetCASC.committed(build, at: output), "committed install can recover interrupted library registration")
    var otherBuild = build; otherBuild.build = String(repeating: "b", count: 32)
    require(!BCDBnetCASC.committed(otherBuild, at: output), "recovery cannot accept a different installed build")
    let program = try Data(contentsOf: output.appendingPathComponent("_classic_era_/WowClassic.exe"))
    require(program == body, "CASC assembly extracts CKey-verified Windows program")
    let packed = try Data(contentsOf: output.appendingPathComponent("Data/data/data.000"))
    require(packed.suffix(raw.count) == raw && packed.count == raw.count + 30, "CASC archive envelope and BLTE layout")
    let key = try BCDBnetNGDP.keyBytes(encoded), bucket = BCDBnetCASC.Entry(key: key, archive: 0, offset: 0, size: Int64(raw.count + 30)).bucket
    let localIndex = try Data(contentsOf: output.appendingPathComponent(String(format: "Data/data/%02x00000001.idx", bucket)))
    require(localIndex.subdata(in: 40..<49) == key.prefix(9), "CASC local index locates installed payload")
    require(FileManager.default.fileExists(atPath: output.appendingPathComponent(".build.info").path), "build metadata is committed with game files")
}
