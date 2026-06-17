//
//  CloudflareAccessTest.swift
//  AmperfyKitTests
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

@testable import AmperfyKit
import XCTest

class CloudflareAccessTest: XCTestCase {
  /// Old persisted credentials (before the feature existed) must decode with the
  /// feature disabled, so existing users are unaffected.
  func testDecodingLegacyCredentialsDefaultsToDisabled() throws {
    let legacyJson = """
    {
      "serverUrl": "https://music.example.com",
      "username": "alice",
      "password": "secret",
      "backendApi": 2,
      "activeBackendServerUrl": "https://music.example.com",
      "alternativeServerURLs": []
    }
    """
    let data = Data(legacyJson.utf8)
    let credentials = try JSONDecoder().decode(LoginCredentials.self, from: data)
    XCTAssertFalse(credentials.isCloudflareAccessEnabled)
    XCTAssertEqual(credentials.cloudflareAccessClientId, "")
    XCTAssertTrue(credentials.cloudflareAccessHeaders.isEmpty)
  }

  func testEncodeDecodeRoundTripPreservesCloudflareConfig() throws {
    var credentials = LoginCredentials(
      serverUrl: "https://music.example.com",
      username: "bob",
      password: "pw"
    )
    credentials.isCloudflareAccessEnabled = true
    credentials.cloudflareAccessClientId = "client-id-123"

    let encoded = try JSONEncoder().encode(credentials)
    let decoded = try JSONDecoder().decode(LoginCredentials.self, from: encoded)
    XCTAssertTrue(decoded.isCloudflareAccessEnabled)
    XCTAssertEqual(decoded.cloudflareAccessClientId, "client-id-123")
  }

  /// Headers must be empty when disabled, even if a secret is present in the Keychain.
  func testHeadersEmptyWhenDisabled() {
    var credentials = LoginCredentials(
      serverUrl: "https://disabled.example.com",
      username: "carol",
      password: "pw"
    )
    let ident = Account.createInfo(credentials: credentials).ident
    CloudflareAccessCredentialStore.shared.setSecret("the-secret", forAccountIdent: ident)
    defer { CloudflareAccessCredentialStore.shared.removeSecret(forAccountIdent: ident) }

    credentials.isCloudflareAccessEnabled = false
    XCTAssertTrue(credentials.cloudflareAccessHeaders.isEmpty)
  }

  func testHeadersPopulatedWhenEnabledWithSecret() {
    var credentials = LoginCredentials(
      serverUrl: "https://enabled.example.com",
      username: "dave",
      password: "pw"
    )
    credentials.isCloudflareAccessEnabled = true
    credentials.cloudflareAccessClientId = "my-client-id"
    let ident = Account.createInfo(credentials: credentials).ident
    CloudflareAccessCredentialStore.shared.setSecret("my-secret", forAccountIdent: ident)
    defer { CloudflareAccessCredentialStore.shared.removeSecret(forAccountIdent: ident) }

    let headers = credentials.cloudflareAccessHeaders
    XCTAssertEqual(headers[LoginCredentials.cloudflareAccessClientIdHeader], "my-client-id")
    XCTAssertEqual(headers[LoginCredentials.cloudflareAccessClientSecretHeader], "my-secret")
  }

  /// When enabled but the secret is missing from the Keychain, no partial headers are sent.
  func testHeadersEmptyWhenSecretMissing() {
    var credentials = LoginCredentials(
      serverUrl: "https://nosecret.example.com",
      username: "erin",
      password: "pw"
    )
    credentials.isCloudflareAccessEnabled = true
    credentials.cloudflareAccessClientId = "client-id"
    let ident = Account.createInfo(credentials: credentials).ident
    CloudflareAccessCredentialStore.shared.removeSecret(forAccountIdent: ident)

    XCTAssertTrue(credentials.cloudflareAccessHeaders.isEmpty)
  }

  func testKeychainStoreRoundTripAndRemoval() {
    let ident = "test-account-\(UUID().uuidString)"
    let store = CloudflareAccessCredentialStore.shared
    defer { store.removeSecret(forAccountIdent: ident) }

    XCTAssertFalse(store.hasSecret(forAccountIdent: ident))
    XCTAssertTrue(store.setSecret("round-trip", forAccountIdent: ident))
    XCTAssertTrue(store.hasSecret(forAccountIdent: ident))
    XCTAssertEqual(store.getSecret(forAccountIdent: ident), "round-trip")

    // Overwrite
    XCTAssertTrue(store.setSecret("updated", forAccountIdent: ident))
    XCTAssertEqual(store.getSecret(forAccountIdent: ident), "updated")

    // Empty secret removes the entry
    XCTAssertTrue(store.setSecret("", forAccountIdent: ident))
    XCTAssertFalse(store.hasSecret(forAccountIdent: ident))
  }

  func testKeychainMigration() {
    let source = "source-\(UUID().uuidString)"
    let dest = "dest-\(UUID().uuidString)"
    let store = CloudflareAccessCredentialStore.shared
    defer {
      store.removeSecret(forAccountIdent: source)
      store.removeSecret(forAccountIdent: dest)
    }

    store.setSecret("to-migrate", forAccountIdent: source)
    store.migrateSecret(fromAccountIdent: source, toAccountIdent: dest)
    XCTAssertFalse(store.hasSecret(forAccountIdent: source))
    XCTAssertEqual(store.getSecret(forAccountIdent: dest), "to-migrate")
  }
}
