# typed: false
# frozen_string_literal: true

# Homebrew formula for Opaque — approval-gated secrets broker for AI coding tools
class Opaque < Formula
  desc "Approval-gated secrets broker for AI coding tools"
  homepage "https://github.com/kcirtapfromspace/opaque"
  version "0.1.0"
  license "BSL-1.1"

  on_macos do
    on_arm do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v#{version}/opaque-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_DARWIN_SHA256"
    end

    on_intel do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v#{version}/opaque-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_64_DARWIN_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v#{version}/opaque-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_AARCH64_LINUX_SHA256"
    end

    on_intel do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v#{version}/opaque-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_X86_64_LINUX_SHA256"
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
