class Mcprism < Formula
  desc "Security scanner for Model Context Protocol servers"
  homepage "https://github.com/HUA503/mcprism"
  url "https://github.com/HUA503/mcprism/archive/refs/tags/v0.9.2.tar.gz"
  sha256 "f1353a1b190cf68c085c2b8ed6c315768f1c9e43a30216a4ff7ec10e9d889026"
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
