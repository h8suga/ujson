#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <sstream>
#include <string>
#include <ujson/ujson.hpp>

using namespace ujson;

namespace {

    struct NullHandler {
        bool on_null() noexcept {
            return true;
        }
        bool on_bool(bool) noexcept {
            return true;
        }
        bool on_number(double) noexcept {
            return true;
        }
        bool on_integer(std::int64_t) noexcept {
            return true;
        }
        bool on_string(std::string_view) noexcept {
            return true;
        }
        bool on_object_begin() noexcept {
            return true;
        }
        bool on_object_end() noexcept {
            return true;
        }
        bool on_array_begin() noexcept {
            return true;
        }
        bool on_array_end() noexcept {
            return true;
        }
        bool on_key(std::string_view) noexcept {
            return true;
        }
    };

    std::string make_large_json(const std::size_t objects) {
        std::string s;
        s.reserve(objects * 64);
        s += "[";

        for (std::size_t i = 0; i < objects; ++i) {
            s += R"({"id":)";
            s += std::to_string(i);
            s += R"(,"name":"player", "alive":true, "score":)";
            s += std::to_string(i * 10);
            s += "}";

            if (i + 1 != objects)
                s += ",";
        }

        s += "]";
        return s;
    }

} // namespace

TEST_CASE("ujson sax parse small", "[ujson][sax][bench]") {
    std::string json = R"({"a":[1,2,3],"b":{"c":4,"d":"x"}})";

    BENCHMARK("sax small") {
        NullHandler h;
        SaxParser parser(h, json);
        return parser.parse();
    };
}

TEST_CASE("ujson sax parse large", "[ujson][sax][bench]") {
    std::string json = make_large_json(2000);

    BENCHMARK("sax large (2000 objects)") {
        NullHandler h;
        SaxParser parser(h, json);
        return parser.parse();
    };
}

TEST_CASE("ujson sax deep nesting", "[ujson][sax][bench]") {
    std::string json;
    for (int i = 0; i < 200; ++i)
        json += "[";
    json += "0";
    for (int i = 0; i < 200; ++i)
        json += "]";

    BENCHMARK("sax deep nesting 200") {
        NullHandler h;
        SaxParser parser(h, json);
        return parser.parse();
    };
}

TEST_CASE("ujson sax string heavy", "[ujson][sax][bench]") {
    std::string json = "[";
    for (int i = 0; i < 5000; ++i) {
        json += R"("some_string_value_here")";
        if (i != 4999)
            json += ",";
    }
    json += "]";

    BENCHMARK("sax 5000 strings") {
        NullHandler h;
        SaxParser parser(h, json);
        return parser.parse();
    };
}

TEST_CASE("ujson dom vs sax compare", "[ujson][bench]") {
    std::string json = make_large_json(2000);

    BENCHMARK("DOM parse 2000 objects") {
        NewAllocator alloc {};
        Arena arena {alloc};
        auto doc = Document::parse(json, arena);
        return doc.ok();
    };

    BENCHMARK("SAX parse 2000 objects") {
        NullHandler h;
        SaxParser parser(h, json);
        return parser.parse();
    };
}
