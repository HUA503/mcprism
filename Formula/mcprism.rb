class Mcprism < Formula
  desc "Security scanner for Model Context Protocol servers"
  homepage "https://github.com/HUA503/mcprism"
  url "https://github.com/HUA503/mcprism/archive/refs/tags/v0.40.0.tar.gz"
  sha256 "4a08e19acf035cbb559f65eda3b816dca07f0671483650970029d4f06e16bb5c"
  license "MIT"

  depends_on "go" => :build

  deny_network_access!

  def fetch
    system "go", "mod", "download"
  end

  def install
    system "go", "build", *std_go_args(ldflags: "-X main.version=#{version}"), "./cmd/mcprism"
  end
end
