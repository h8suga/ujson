#include <catch2/catch_session.hpp>
#include <catch2/catch_test_macros.hpp>
#include <iostream>

inline std::string bench_environment() {
    std::ostringstream ss;

#if defined(_MSC_VER)
    ss << "Compiler: MSVC " << _MSC_VER << "\n";
#elif defined(__clang__)
    ss << "Compiler: Clang " << __clang_major__ << "." << __clang_minor__ << "\n";
#elif defined(__GNUC__)
    ss << "Compiler: GCC " << __GNUC__ << "." << __GNUC_MINOR__ << "\n";
#endif

#if defined(__AVX2__)
    ss << "AVX2: enabled\n";
#else
    ss << "AVX2: disabled\n";
#endif

#ifdef _WIN32
    ss << "OS: Windows\n";
#elif defined(__linux__)
    ss << "OS: Linux\n";
#endif

    return ss.str();
}

int main(int argc, char* argv[]) {
    std::cout << bench_environment() << "\n";
    return Catch::Session().run(argc, argv);
}
