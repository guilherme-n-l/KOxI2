{
  description = "KOxI project runtime environment";

  inputs.koxi.url = "github:guilherme-n-l/KOxI2";

  outputs =
    { koxi, ... }:
    {
      # The upstream runtime shell — the koxi binary plus everything
      # the pipeline shells out to — as this project's default shell.
      devShells = builtins.mapAttrs (_system: shells: {
        default = shells.koxi;
      }) koxi.devShells;

      packages = koxi.packages;
    };
}
