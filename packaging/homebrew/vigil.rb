# Homebrew formula for Vigil.
# Rendered by sync.py; @VERSION@ and the @SHA256_*@ values are filled in by the
# release workflow (job "publish", step "Render package-manager manifests") and
# shipped in vigil-<version>-package-manifests.tar.gz. Copy the rendered file
# into the tap repository (LLCForge/homebrew-tap, Formula/vigil.rb).
class Vigil < Formula
  desc "Real-time BGP origin hijack detection over public route collector feeds"
  homepage "https://github.com/LLCForge/Vigil"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/LLCForge/Vigil/releases/download/v@VERSION@/vigil-@VERSION@-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/LLCForge/Vigil/releases/download/v@VERSION@/vigil-@VERSION@-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/LLCForge/Vigil/releases/download/v@VERSION@/vigil-@VERSION@-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/LLCForge/Vigil/releases/download/v@VERSION@/vigil-@VERSION@-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_LINUX_MUSL@"
    end
  end

  def install
    bin.install "vigil"
    pkgetc.install "vigil.example.toml" if File.exist?("vigil.example.toml")
    doc.install Dir["README*.md"]
  end

  service do
    run [opt_bin/"vigil", "run", "--config", etc/"vigil/vigil.toml"]
    environment_variables STATE_DIRECTORY: var/"lib/vigil"
    keep_alive successful_exit: false
    log_path var/"log/vigil.log"
    error_log_path var/"log/vigil.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/vigil --version")
  end
end
