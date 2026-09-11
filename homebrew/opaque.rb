# typed: false
# frozen_string_literal: true

# Homebrew formula for Opaque — approval-gated secrets broker for AI coding tools
class Opaque < Formula
  desc "Approval-gated secrets broker for AI coding tools"
  homepage "https://github.com/kcirtapfromspace/opaque"
  license "BUSL-1.1"

  on_macos do
    on_arm do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.2.0/opaque-0.2.0-aarch64-apple-darwin.tar.gz"
      sha256 "e186a9cbc10797242b6b5f3f425a776838876a594e63af8a8b245fd6530f2cef"
    end

    on_intel do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.2.0/opaque-0.2.0-x86_64-apple-darwin.tar.gz"
      sha256 "19f9e380b78724c3413ac98c05896cb7f4f7fcc804088fb5603ab60bde03e378"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.2.0/opaque-0.2.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "b5537279e7ed3c623a0977e2fee4f8d27b4f50081f6de1c3059acd4e3f875375"
    end

    on_intel do
      url "https://github.com/kcirtapfromspace/opaque/releases/download/v0.2.0/opaque-0.2.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "3c09616dc16a72408f28749bc698e3385dfa42aef96ea39acd578ac00b6a089d"
    end
  end

  def install
    bin.install "opaqued"
    bin.install "opaque"
    bin.install "opaque-mcp"
    bin.install "opaque-approve-helper"
    bin.install "opaque-web"
    # Older tagged archives predate these tools. A release containing them must
    # make them available without breaking installation of the existing tags.
    bin.install "opaque-approver" if File.file?("opaque-approver")
    bin.install "opaque-evidence" if File.file?("opaque-evidence")
    prefix.install "Opaque Reviewer.app" if OS.mac? && File.directory?("Opaque Reviewer.app")
  end

  def caveats
    return unless OS.mac? && (prefix/"Opaque Reviewer.app").directory?

    <<~EOS
      The trusted reviewer is available at:
        #{prefix}/Opaque Reviewer.app
      Follow its enrollment guide before reviewing work:
        https://github.com/kcirtapfromspace/opaque/blob/main/crates/opaque-approver/README.md
      Installing the formula does not enroll a broker or register a notice handler.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/opaque --version")
  end
end
