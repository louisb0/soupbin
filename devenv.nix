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
      if [ -z "$1" ]; then
        echo "Usage: <cmd> <debug|release|profile>"
        exit 1
      fi

      BUILD_TYPE=$(echo $1 | tr '[:upper:]' '[:lower:]')

      case $BUILD_TYPE in
        debug)   CMAKE_BUILD_TYPE=Debug ;;
        release) CMAKE_BUILD_TYPE=Release ;;
        profile) CMAKE_BUILD_TYPE=Profile ;;
        *)
          echo "Error: Unknown build type '$1'"
          echo "Valid options: debug, release, profile"
          exit 1
          ;;
      esac

      mkdir -p build/$BUILD_TYPE
      cmake -B build/$BUILD_TYPE -S . -DCMAKE_BUILD_TYPE=$CMAKE_BUILD_TYPE

      ln -sf build/$BUILD_TYPE/compile_commands.json compile_commands.json
    '';

    build.exec = ''
      setup "$1" && cmake --build build/$(echo $1 | tr '[:upper:]' '[:lower:]')
    '';

    clean.exec = ''
      if [ -z "$1" ]; then
        echo "Usage: clean <debug|release|profile|all>"
        exit 1
      fi

      BUILD_TYPE=$(echo $1 | tr '[:upper:]' '[:lower:]')

      case $BUILD_TYPE in
        debug|release|profile)
          rm -rf build/$BUILD_TYPE
          ;;
        all)
          rm -rf build
          ;;
        *)
          echo "Error: Unknown build type '$1'"
          echo "Valid options: debug, release, profile, all"
          exit 1
          ;;
      esac
    '';

    iwyu.exec = ''
      output=$(iwyu_tool.py -p build/debug client/ server/ example/  2>&1 | grep -v "no private include name for @headername mapping")
      echo "$output"
      echo "$output" | grep -q "should add these lines:" && exit 1 || exit 0
    '';
  };
}
