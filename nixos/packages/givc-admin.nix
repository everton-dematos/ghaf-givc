{
  lib,
  pkgs,
  crane,
  protobuf,
  src,
}:
let
  craneLib = crane.mkLib pkgs;

  protoFilter = path: _type: null != builtins.match ".*proto$" path;
  protoOrCargo = path: type: (protoFilter path type) || (craneLib.filterCargoSources path type);
  # Common arguments can be set here to avoid repeating them later
  # Note: changes here will rebuild all dependency crates
  commonArgs = {
    pname = "givc";
    version = "0.0.1";
    src = lib.cleanSourceWith {
      src = craneLib.path src;
      filter = protoOrCargo;
    };

    strictDeps = true;

    nativeBuildInputs = [
      protobuf
      pkgs.pkg-config
    ];

    buildInputs =
      pkgs.lib.optionals pkgs.stdenv.isDarwin [
        # Additional darwin specific inputs can be set here
        pkgs.libiconv
      ]
      ++ [
        pkgs.systemd.dev
      ];

    # Needed for pkg-config to find libsystemd
    PKG_CONFIG_PATH = "${pkgs.systemd.dev}/lib/pkgconfig";
  };

  givc = craneLib.buildPackage (
    commonArgs
    // {
      outputs = [
        "out"
        "cli"
        "agent"
        "update_server"
        "ota"
      ];
      cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      # Additional environment variables or build phases/hooks can be set
      # here *without* rebuilding all dependency crates
      # MY_CUSTOM_VAR = "some value";
      postUnpack = ''
        # Avoid issue with source filtering, put symlink back into source tree
        ln -sf ../../api $sourceRoot/crates/common/api
      '';
      postInstall = ''
        mkdir -p $cli/bin $agent/bin $update_server/bin $ota/bin
        mv $out/bin/givc-cli $cli/bin/givc-cli
        mv $out/bin/givc-agent $agent/bin/givc-agent
        mv $out/bin/update-server $update_server/bin/ota-update-server
        mv $out/bin/ota-update $ota/bin/ota-update

        # Install Sigma rules directory
        mkdir -p $out/share/givc
        cp -r crates/admin/src/admin/sigma_all_rules $out/share/givc/
      '';
    }
  );
in
givc
