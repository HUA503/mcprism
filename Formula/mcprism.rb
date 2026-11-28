class Mcprism < Formula
  desc "Security scanner for Model Context Protocol servers"
  homepage "https://github.com/HUA503/mcprism"
  url "https://github.com/HUA503/mcprism/archive/refs/tags/v0.43.4.tar.gz"
  sha256 "4ed37cedb953aba9731ccd38736f3bceb0437cba90806db3e7c86a133574eb27"
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
