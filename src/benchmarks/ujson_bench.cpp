#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <ujson/ujson.hpp>

#include <random>
#include <string>
#include <vector>

using namespace ujson;

using TestDocument = DocumentView;

struct VectorAlloc {
    static constexpr auto kBlockSize = kDefaultBlockSize;

    std::vector<char>* buf {};

    void* allocate(const std::size_t size, const std::size_t align) {
        std::size_t offset = buf->size();
        std::size_t aligned = (offset + align - 1) & ~(align - 1);

        if (aligned + size > buf->capacity())
            return nullptr;

        buf->resize(aligned + size);
        return buf->data() + aligned;
    }

    void deallocate(void*, std::size_t, std::size_t) noexcept {
        // arena reset handles lifetime
    }
};

static VectorAlloc make_alloc(std::vector<char>& storage) {
    storage.clear();
    storage.reserve(16 * 1024 * 1024);
    return VectorAlloc {&storage};
}

static std::string large_json() {
    std::string s = R"({"items":[)";
    for (int i = 0; i < 2000; ++i) {
        s += R"({"id":)";
        s += std::to_string(i);
        s += R"(,"name":"item)";
        s += std::to_string(i);
        s += R"(","value":)";
        s += std::to_string(i * 3);
        s += "}";
        if (i != 1999)
            s += ",";
    }
    s += "]}";
    return s;
}

static std::string deep_json(const int depth) {
    std::string s;
    for (int i = 0; i < depth; ++i)
        s += "[";
    s += "0";
    for (int i = 0; i < depth; ++i)
        s += "]";
    return s;
}

TEST_CASE("ujson parse benchmark", "[ujson][bench]") {

    static const std::string json = R"({
        "b": true,
        "i": 42,
        "f": 3.5,
        "s": "hello",
        "arr": [1,2,3,4,5,6,7,8],
        "obj": {"a":1,"b":2,"c":3}
    })";

    BENCHMARK("parse DOM small") {
        std::vector<char> mem;
        auto alloc = make_alloc(mem);
        Arena arena {alloc};
        auto doc = TestDocument::parse(json, arena);
        REQUIRE(doc.ok());
        return doc.root().size();
    };

    BENCHMARK("validate-only small") {
        REQUIRE(ujson::validate(json).ok());
        return true;
    };
}

TEST_CASE("ujson large JSON benchmark", "[ujson][bench]") {

    static const std::string big = large_json();

    BENCHMARK("parse DOM large (2000 objects)") {
        std::vector<char> mem;
        auto alloc = make_alloc(mem);
        Arena arena {alloc};
        auto doc = TestDocument::parse(big, arena);
        REQUIRE(doc.ok());
        return doc.root().get("items").size();
    };

    BENCHMARK("validate-only large") {
        REQUIRE(ujson::validate(big).ok());
        return true;
    };
}

TEST_CASE("ujson deep nesting benchmark", "[ujson][bench]") {

    static const std::string deep = deep_json(200);

    BENCHMARK("parse deep nesting") {
        std::vector<char> mem;
        auto alloc = make_alloc(mem);
        Arena arena {alloc};
        auto doc = TestDocument::parse(deep, arena);
        REQUIRE(doc.ok());
        return doc.root().size();
    };

    BENCHMARK("validate deep nesting") {
        REQUIRE(ujson::validate(deep).ok());
        return true;
    };
}

TEST_CASE("ujson encode benchmark", "[ujson][bench]") {

    static const std::string json = large_json();

    std::vector<char> mem;
    auto alloc = make_alloc(mem);
    Arena arena {alloc};
    auto doc = TestDocument::parse(json, arena);
    REQUIRE(doc.ok());

    BENCHMARK("encode large JSON") {
        return encode(doc.root());
    };
}

TEST_CASE("ujson object lookup benchmark", "[ujson][bench][lookup]") {

    static const std::string json = large_json();

    std::vector<char> mem;
    auto alloc = make_alloc(mem);
    Arena arena {alloc};
    auto doc = TestDocument::parse(json, arena);
    REQUIRE(doc.ok());

    auto items = doc.root().get("items");

    BENCHMARK("array iteration + field lookup") {
        [[maybe_unused]] int sum = 0;
        items.for_each([&](const ValueRef v) { sum += static_cast<int>(v.get("value").as_double()); });
        return sum;
    };
}

TEST_CASE("ujson builder benchmark", "[ujson][bench]") {
    BENCHMARK("build + encode 1000 objects") {

        std::vector<char> mem;
        auto alloc = make_alloc(mem);
        Arena arena {alloc};
        DomBuilder b {arena};

        b.array([&] {
            for (int i = 0; i < 1000; ++i) {
                b.object([&] {
                    b["id"] = i;
                    b["name"] = std::string_view {"item"};
                });
            }
        });

        return b.encode();
    };
}

TEST_CASE("ujson parse benchmark scaling", "[ujson][bench][scale]") {
    static constexpr std::string_view chunk = R"({"b":true,"i":42,"f":3.5,"s":"hello","arr":[1,2,3,4,5,6,7,8],"obj":{"a":1,"b":2,"c":3}})";

    auto make_big = [](int n) {
        std::string s;
        s.reserve(static_cast<size_t>(n) * (chunk.size() + 1) + 16);
        s.push_back('[');
        for (int i = 0; i < n; ++i) {
            if (i)
                s.push_back(',');
            s.append(chunk);
        }
        s.push_back(']');
        return s;
    };

    const auto big16 = make_big(16);
    const auto big64 = make_big(64);

    static constexpr std::size_t kBuf = 512 * 1024;
    ujson::StaticBufferAllocator<kBuf> alloc;
    ujson::Arena arena {alloc};

    BENCHMARK("parse DOM x16 (same arena)") {
        alloc.reset();
        arena.reset();
        auto doc = ujson::Document::parse(std::string_view {big16}, arena);
        REQUIRE(doc.ok());
        return doc.root().size();
    };

    BENCHMARK("parse DOM x64 (same arena)") {
        alloc.reset();
        arena.reset();
        auto doc = ujson::Document::parse(std::string_view {big64}, arena);
        REQUIRE(doc.ok());
        return doc.root().size();
    };

    BENCHMARK_ADVANCED("parse DOM x64 (advanced)")(Catch::Benchmark::Chronometer meter) {
        meter.measure([&] {
            alloc.reset();
            arena.reset();
            auto doc = ujson::Document::parse(std::string_view {big64}, arena);
            REQUIRE(doc.ok());
            return doc.root().size();
        });
    };
}

TEST_CASE("ujson parse benchmark (same arena)", "[ujson][bench]") {
    static constexpr std::string_view json = R"({
        "b": true,
        "i": 42,
        "f": 3.5,
        "s": "hello",
        "arr": [1,2,3,4,5,6,7,8],
        "obj": {"a":1,"b":2,"c":3}
    })";

    static constexpr std::size_t kBuf = 256 * 1024;
    ujson::StaticBufferAllocator<kBuf> alloc;
    ujson::Arena arena {alloc};

    BENCHMARK("parse DOM small (same arena)") {
        alloc.reset();
        arena.reset();
        auto doc = ujson::Document::parse(json, arena);
        REQUIRE(doc.ok());
        return doc.root().size();
    };

    BENCHMARK("validate-only small (same arena)") {
        alloc.reset();
        arena.reset();

        ujson::ValidateHandler h {arena};
        ujson::CoreParser<false, true, ujson::ValidateHandler> p(h, json, 512);
        const auto err = p.parse_root();
        REQUIRE(err.ok());
        return true;
    };
}
