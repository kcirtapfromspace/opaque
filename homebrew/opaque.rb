# typed: false
# frozen_string_literal: true

# Homebrew formula for Opaque — approval-gated secrets broker for AI coding tools
class Opaque < Formula
  desc "Approval-gated secrets broker for AI coding tools"
  homepage "https://github.com/kcirtapfromspace/opaque"
  license "BUSL-1.1"

  on_macos do
    on_arm do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.1.0/opaque-0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "bc24da2c7244a8b858064642cc0f65bcd17f8db6d370aad767914432ddfe0cd3"
    end

    on_intel do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.1.0/opaque-0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "51a59d3d56326c6cc9921826f123b6d97a56a9340fb787cd8ae9a9943fbcb17a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.1.0/opaque-0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "cf14cb23e04c300ac6155ed84f1e475364f77f9d6eeb34d0b79b470e6186dd19"
    end

    on_intel do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.1.0/opaque-0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "75ef2eef223c60457da58681933bb79f77741e5535cda8f8873794993f7c03dc"
    end
  end

  def install
    bin.install "opaqued"
    bin.install "opaque"
    bin.install "opaque-mcp"
    bin.install "opaque-approve-helper"
    bin.install "opaque-web"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/opaque --version")
  end
end
