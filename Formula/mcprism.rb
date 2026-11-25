class Mcprism < Formula
  desc "Security scanner for Model Context Protocol servers"
  homepage "https://github.com/HUA503/mcprism"
  url "https://github.com/HUA503/mcprism/archive/refs/tags/v0.10.0.tar.gz"
  sha256 "a79cc9aa22235f619983c29c06e6b4d90dbb01a4a4b1b5511a1ad4ccbba18e95"
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
