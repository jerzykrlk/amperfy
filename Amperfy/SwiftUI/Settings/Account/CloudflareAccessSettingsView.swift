//
//  CloudflareAccessSettingsView.swift
//  Amperfy
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

import AmperfyKit
import SwiftUI

// MARK: - CloudflareAccessSettingsView

struct CloudflareAccessSettingsView: View {
  @Binding
  var isVisible: Bool

  @State
  var isEnabled = false
  @State
  var clientIdInput = ""
  // The stored secret is never read back into the UI. An empty field means "keep existing".
  @State
  var clientSecretInput = ""
  @State
  var hasStoredSecret = false
  @State
  var errorMsg = ""
  @State
  var successMsg = ""

  @EnvironmentObject
  var settings: Settings

  private func loadCurrentValues() {
    errorMsg = ""
    successMsg = ""
    guard let activeAccountInfo = settings.activeAccountInfo,
          let credentials = appDelegate.storage.settings.accounts.getSetting(activeAccountInfo)
          .read.loginCredentials
    else { return }
    isEnabled = credentials.isCloudflareAccessEnabled
    clientIdInput = credentials.cloudflareAccessClientId
    hasStoredSecret = CloudflareAccessCredentialStore.shared
      .hasSecret(forAccountIdent: activeAccountInfo.ident)
    clientSecretInput = ""
  }

  private func save() {
    errorMsg = ""
    successMsg = ""
    guard let activeAccountInfo = settings.activeAccountInfo else {
      errorMsg = "No active account."
      return
    }

    if isEnabled {
      let clientId = clientIdInput.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !clientId.isEmpty else {
        errorMsg = "Please provide a Client ID."
        return
      }
      let willHaveSecret = !clientSecretInput.isEmpty || hasStoredSecret
      guard willHaveSecret else {
        errorMsg = "Please provide a Client Secret."
        return
      }
      if !clientSecretInput.isEmpty {
        CloudflareAccessCredentialStore.shared.setSecret(
          clientSecretInput,
          forAccountIdent: activeAccountInfo.ident
        )
      }
      applyCredentialsUpdate(
        activeAccountInfo: activeAccountInfo,
        enabled: true,
        clientId: clientId
      )
    } else {
      // Disabling: remove the stored secret and clear the configuration.
      CloudflareAccessCredentialStore.shared.removeSecret(forAccountIdent: activeAccountInfo.ident)
      applyCredentialsUpdate(activeAccountInfo: activeAccountInfo, enabled: false, clientId: "")
    }

    successMsg = "Cloudflare Access settings saved."
    clientSecretInput = ""
    hasStoredSecret = CloudflareAccessCredentialStore.shared
      .hasSecret(forAccountIdent: activeAccountInfo.ident)
  }

  private func applyCredentialsUpdate(
    activeAccountInfo: AccountInfo,
    enabled: Bool,
    clientId: String
  ) {
    appDelegate.storage.settings.accounts.updateSetting(activeAccountInfo) { accountSettings in
      accountSettings.loginCredentials?.isCloudflareAccessEnabled = enabled
      accountSettings.loginCredentials?.cloudflareAccessClientId = clientId
    }
    if let updated = appDelegate.storage.settings.accounts.getSetting(activeAccountInfo).read
      .loginCredentials {
      appDelegate.getMeta(activeAccountInfo).backendApi.provideCredentials(credentials: updated)
    }
  }

  var body: some View {
    ZStack {
      List {
        Section {
          VStack(spacing: 20) {
            Text("Cloudflare Access Service Token")
              .font(.title2).fontWeight(.bold).padding(.all, 10)

            if !successMsg.isEmpty {
              InfoBannerView(message: successMsg, color: .success)
            }
            if !errorMsg.isEmpty {
              InfoBannerView(message: errorMsg, color: .error)
            }

            Toggle("Enable Service Token", isOn: $isEnabled)

            if isEnabled {
              VStack(spacing: 5) {
                TextField("Client ID", text: $clientIdInput)
                  .textFieldStyle(.roundedBorder)
                  .autocorrectionDisabled(true)
                  .textInputAutocapitalization(.never)
                SecureField(
                  hasStoredSecret ? "Client Secret (leave blank to keep)" : "Client Secret",
                  text: $clientSecretInput
                )
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled(true)
                .textInputAutocapitalization(.never)
              }
            }
          }

          HStack {
            Button(action: { isVisible = false }) {
              HStack { Spacer(); Text("Cancel").fontWeight(.semibold); Spacer() }
            }
            .buttonStyle(DefaultButtonStyle())
            Spacer()
            Button(action: { save() }) {
              HStack { Spacer(); Text("Save"); Spacer() }
            }
            .buttonStyle(DefaultButtonStyle())
          }
          .padding([.top], 8)
        }
        #if targetEnvironment(macCatalyst) /// ok
        .listRowBackground(Color.clear)
        #else
        .padding()
        #endif
      }
      #if targetEnvironment(macCatalyst) // ok
      .listStyle(.plain)
      #endif
    }
    .onAppear {
      loadCurrentValues()
    }
  }
}
