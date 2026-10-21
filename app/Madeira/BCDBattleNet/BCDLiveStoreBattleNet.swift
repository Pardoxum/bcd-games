// SPDX-License-Identifier: GPL-3.0-only
// Copyright 2026 thebcd69 (BCD)
// BCD Material: additional terms under GPL-3.0 section 7 apply; see LICENSE-BCD.md.

import Foundation

extension BCDLiveStore {
    func battleNetAccount() -> BCDAccount {
        let account = BCDBattleNet.shared
        return BCDAccount(store: .battlenet, name: account.signedIn ? (account.name ?? "Battle.net account") : nil, available: true)
    }

    /// Imported WoW clients retain their library IDs, settings, play history and ordinary Play.
    /// Account discovery adds missing flavours without claiming to have installed them.
    func battleNetMerge(_ games: inout [BCDGame]) {
        let account = BCDBattleNet.shared
        account.start()
        var installed = Set<String>()
        for entry in LibraryModel.shared.entries {
            guard entry.desktop != true, entry.steamAppID == nil,
                  let product = BCDBattleNetAccount.installedProduct(entry.relativePath),
                  let index = games.firstIndex(where: { $0.id == BCDLiveID.local(entry.id) }) else { continue }
            games[index].store = .battlenet
            installed.insert(product)
        }
        for product in account.products where !installed.contains(product.id) {
            games.append(BCDGame(id: "battlenet." + product.id, title: product.title, store: .battlenet, state: .notInstalled))
        }
    }
}
