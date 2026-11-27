{
  description = "Security scanner for Model Context Protocol servers";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      version = "0.31.0";
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          mcprism = pkgs.buildGoModule {
            pname = "mcprism";
            inherit version;
            src = self;
            vendorHash = "sha256-H0WiIx+jG1zVUsKIsDhMC4/C4DRMhtgw/iXRxGwlGrE=";
            doCheck = false;
            subPackages = [ "cmd/mcprism" ];
            ldflags = [ "-s" "-w" "-X main.version=v${version}" ];

            meta = with pkgs.lib; {
              description = "Security scanner for Model Context Protocol servers";
              homepage = "https://github.com/HUA503/mcprism";
              license = licenses.mit;
              mainProgram = "mcprism";
              platforms = systems;
            };
          };
        in
        {
          default = mcprism;
          mcprism = mcprism;
        });
    };
}

