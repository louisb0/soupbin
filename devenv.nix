{pkgs, ...}: {
  languages.cplusplus.enable = true;

  packages = with pkgs; [
    alejandra
    include-what-you-use
    clang-tools
    perf-tools
    valgrind
    gdb
  ];

  git-hooks.hooks = {
    alejandra = {
      enable = true;
      settings.check = true;
    };

    clang-format = {
      enable = true;
      entry = "${pkgs.clang-tools}/bin/clang-format --dry-run -Werror";
    };

    clang-tidy = {
      enable = true;
      entry = "${pkgs.clang-tools}/bin/clang-tidy -p build/debug";
    };
  };

  scripts = {
    setup.exec = ''
      BUILD_TYPE=''${1:-debug}
      BUILD_TYPE=$(echo $BUILD_TYPE | tr '[:upper:]' '[:lower:]')

      case $BUILD_TYPE in
        debug)   CMAKE_BUILD_TYPE=Debug ;;
        release) CMAKE_BUILD_TYPE=Release ;;
        profile) CMAKE_BUILD_TYPE=Profile ;;
        *) echo "Unknown build type: $BUILD_TYPE"; exit 1 ;;
      esac

      mkdir -p build/$BUILD_TYPE
      cmake -B build/$BUILD_TYPE -S . -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE

      ln -sf build/$BUILD_TYPE/compile_commands.json compile_commands.json
    '';

    build.exec = ''
      BUILD_TYPE=''${1:-debug}
      BUILD_TYPE=$(echo $BUILD_TYPE | tr '[:upper:]' '[:lower:]')

      setup $BUILD_TYPE
      cmake --build build/$BUILD_TYPE
    '';

    clean.exec = ''
      BUILD_TYPE=''${1:-debug}
      BUILD_TYPE=$(echo $BUILD_TYPE | tr '[:upper:]' '[:lower:]')

      rm -rf build/$BUILD_TYPE
    '';

    # Convenience
    bdebug.exec = ''
      build debug
    '';
    brelease.exec = ''
      build release
    '';
    bprofile.exec = ''
      build profile
    '';
  };
}
