//
//  CloudflareAccessCredentialStore.swift
//  AmperfyKit
//
//  Created by Jerzy Królak on 17.06.26.
//  Copyright (c) 2026 Maximilian Bauer. All rights reserved.
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

import Foundation
import Security

/// Securely stores Cloudflare Access service-token client secrets in the iOS Keychain.
///
/// Only the secret is kept here. The client id and the enabled flag live in
/// `LoginCredentials` (UserDefaults), since they are not sensitive. The secret is
/// keyed by account ident so each server has its own entry.
public final class CloudflareAccessCredentialStore: Sendable {
  public static let shared = CloudflareAccessCredentialStore()

  private static let service = "amperfy.cloudflareAccess.clientSecret"

  private init() {}

  /// Stores (or replaces) the client secret for the given account ident.
  /// Passing an empty string removes the entry.
  @discardableResult
  public func setSecret(_ secret: String, forAccountIdent ident: String) -> Bool {
    guard !secret.isEmpty else {
      return removeSecret(forAccountIdent: ident)
    }
    guard let data = secret.data(using: .utf8) else { return false }

    var query = baseQuery(forAccountIdent: ident)
    let attributes: [String: Any] = [
      kSecValueData as String: data,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
    ]

    let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    if updateStatus == errSecSuccess {
      return true
    }
    if updateStatus == errSecItemNotFound {
      query[kSecValueData as String] = data
      query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
      return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }
    return false
  }

  /// Returns the stored client secret for the given account ident, if present.
  public func getSecret(forAccountIdent ident: String) -> String? {
    var query = baseQuery(forAccountIdent: ident)
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess,
          let data = result as? Data,
          let secret = String(data: data, encoding: .utf8)
    else { return nil }
    return secret
  }

  public func hasSecret(forAccountIdent ident: String) -> Bool {
    var query = baseQuery(forAccountIdent: ident)
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    return SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess
  }

  @discardableResult
  public func removeSecret(forAccountIdent ident: String) -> Bool {
    let query = baseQuery(forAccountIdent: ident)
    let status = SecItemDelete(query as CFDictionary)
    return status == errSecSuccess || status == errSecItemNotFound
  }

  /// Moves a secret stored under one ident to another. Used during login, when the
  /// account ident is finalised only after the backend API type is detected.
  public func migrateSecret(fromAccountIdent source: String, toAccountIdent destination: String) {
    guard source != destination, let secret = getSecret(forAccountIdent: source) else { return }
    setSecret(secret, forAccountIdent: destination)
    removeSecret(forAccountIdent: source)
  }

  private func baseQuery(forAccountIdent ident: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: Self.service,
      kSecAttrAccount as String: ident,
    ]
  }
}
