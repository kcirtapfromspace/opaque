# typed: false
# frozen_string_literal: true

class Opaque < Formula
  desc "Approval-gated secrets broker for AI coding tools"
  homepage "https://github.com/anthropics/opaque"
  version "0.1.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/anthropics/opaque/releases/download/v#{version}/opaque-v#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end

    on_intel do
      url "https://github.com/anthropics/opaque/releases/download/v#{version}/opaque-v#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "opaqued"
    bin.install "opaque"
    bin.install "opaque-mcp"
    bin.install "opaque-approve-helper"
    bin.install "opaque-web"
  end

  def caveats
    <<~EOS
      To get started, run:

        opaque init

      This will create a default configuration and set up the daemon.
    EOS
  end

  test do
    assert_match "opaque", shell_output("#{bin}/opaque --help")
  end
end
