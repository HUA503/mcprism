class Mcprism < Formula
  desc "Security scanner for Model Context Protocol servers"
  homepage "https://github.com/HUA503/mcprism"
  url "https://github.com/HUA503/mcprism/archive/refs/tags/v0.16.0.tar.gz"
  sha256 "8470883345bd420fef4a0aba0571963abffedacf794c4424f824891b89eac083"
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
