#pragma once
// engine/src/detection/rule.hpp
// Built-in SIEM detection rules used by RuleEngine.

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "types.hpp"

namespace aegis::detection {

namespace detail {

inline std::string to_lower_ascii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

inline bool contains_ci(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    const std::string hay = to_lower_ascii(haystack);
    const std::string ned = to_lower_ascii(needle);
    return hay.find(ned) != std::string::npos;
}

inline bool contains_any_ci(std::string_view haystack,
                            std::initializer_list<std::string_view> needles) {
    for (auto n : needles) {
        if (contains_ci(haystack, n)) return true;
    }
    return false;
}

inline bool ends_with_ci(std::string_view value, std::string_view suffix) {
    if (suffix.size() > value.size()) return false;
    return to_lower_ascii(value.substr(value.size() - suffix.size())) == to_lower_ascii(suffix);
}

inline bool is_temp_like_path(std::string_view path) {
    return contains_any_ci(path,
                           {"/tmp/", "/var/tmp/", "/dev/shm/", "\\temp\\", "\\appdata\\local\\temp\\"});
}

inline bool is_sensitive_file(std::string_view path) {
    return contains_any_ci(path,
                           {"/etc/shadow", "/etc/sudoers", "/root/.ssh/", "id_rsa", "\\system32\\config\\sam",
                            "\\windows\\ntds\\ntds.dit"});
}

inline bool is_common_benign_port(uint32_t port) {
    static constexpr std::array<uint32_t, 11> SAFE_PORTS{
        22, 25, 53, 80, 123, 443, 465, 587, 3389, 8080, 8443};
    return std::any_of(SAFE_PORTS.begin(), SAFE_PORTS.end(),
                       [port](uint32_t p) { return p == port; });
}

inline bool suspicious_execution_signal(const nlohmann::json& proc,
                                        std::string& reason_out) {
    const std::string name = proc.value("name", "");
    const std::string exe = proc.value("exe", "");
    const std::string cmdline = proc.value("cmdline", "");

    if (contains_any_ci(cmdline, {"curl ", "wget "}) &&
        contains_any_ci(cmdline, {"| sh", "|sh", "| bash", "|bash"})) {
        reason_out = "download-and-execute pattern";
        return true;
    }
    if (contains_any_ci(cmdline, {"powershell", "pwsh"}) &&
        contains_any_ci(cmdline, {" -enc ", " -encodedcommand "})) {
        reason_out = "encoded powershell command";
        return true;
    }
    if (contains_any_ci(cmdline, {"certutil", "bitsadmin"}) &&
        contains_any_ci(cmdline, {"http://", "https://"})) {
        reason_out = "living-off-the-land downloader pattern";
        return true;
    }
    if (contains_any_ci(name, {"bash", "sh", "powershell", "pwsh"}) &&
        contains_any_ci(cmdline, {"base64 -d", "frombase64string", "invoke-expression", "iex "})) {
        reason_out = "encoded script execution";
        return true;
    }
    if (!exe.empty() && !contains_any_ci(exe, {"/bin/", "/usr/bin/", "\\windows\\system32\\"}) &&
        contains_any_ci(name, {"sh", "bash", "powershell", "pwsh"})) {
        reason_out = "script interpreter launched from unusual executable path";
        return true;
    }
    return false;
}

inline bool has_write_flag(const nlohmann::json& flags) {
    if (!flags.is_array()) return false;
    for (const auto& f : flags) {
        if (!f.is_string()) continue;
        const std::string flag = to_lower_ascii(f.get<std::string>());
        if (flag.find("o_wronly") != std::string::npos ||
            flag.find("o_rdwr") != std::string::npos ||
            flag.find("o_creat") != std::string::npos ||
            flag.find("o_trunc") != std::string::npos ||
            flag.find("o_append") != std::string::npos) {
            return true;
        }
    }
    return false;
}

inline std::string fallback_process_key(const nlohmann::json& net, const ParsedEvent& ev) {
    const std::string pg = net.value("process_guid", ev.process_guid);
    if (!pg.empty()) return pg;
    return "pid:" + std::to_string(net.value("pid", 0u));
}

}  // namespace detail

class BaseRule {
public:
    virtual ~BaseRule() = default;

    virtual std::string_view id() const noexcept = 0;
    virtual std::string_view name() const noexcept = 0;
    virtual Severity severity() const noexcept = 0;
    virtual uint32_t risk_score() const noexcept = 0;
    virtual std::vector<std::string> tags() const { return {}; }

    virtual std::optional<RuleMatch> evaluate(const ParsedEvent& event) const = 0;

protected:
    RuleMatch make_match(const ParsedEvent& ev,
                         std::string summary,
                         nlohmann::json context = {}) const {
        RuleMatch m;
        m.rule_id = std::string(id());
        m.rule_name = std::string(name());
        m.severity = severity();
        m.risk_score = risk_score();
        m.summary = std::move(summary);
        m.context = std::move(context);
        m.tags = tags();
        m.event_id = ev.event_id;
        m.host = ev.host;
        m.tenant_id = ev.tenant_id;
        m.event_ts = ev.ts;
        m.process_guid = ev.process_guid;
        return m;
    }
};

class RansomwareShadowCopyDeleteRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "windows-shadow-copy-delete"; }
    std::string_view name() const noexcept override { return "Potential Ransomware Shadow Copy Deletion"; }
    Severity severity() const noexcept override { return Severity::Critical; }
    uint32_t risk_score() const noexcept override { return 94; }
    std::vector<std::string> tags() const override {
        return {"impact", "ransomware", "windows", "defense-evasion"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "process_start") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("process")) return std::nullopt;
        const auto& proc = payload.at("process");

        const std::string name = proc.value("name", "");
        const std::string cmdline = proc.value("cmdline", "");

        bool suspicious = false;
        std::string reason;

        if (detail::contains_ci(cmdline, "vssadmin") &&
            detail::contains_ci(cmdline, "delete") &&
            detail::contains_ci(cmdline, "shadows")) {
            suspicious = true;
            reason = "vssadmin shadow copy deletion";
        } else if (detail::contains_ci(cmdline, "wbadmin") && detail::contains_ci(cmdline, "delete")) {
            suspicious = true;
            reason = "wbadmin backup catalog deletion";
        } else if (detail::contains_ci(cmdline, "bcdedit") &&
                   detail::contains_any_ci(cmdline, {"recoveryenabled no", "bootstatuspolicy ignoreallfailures"})) {
            suspicious = true;
            reason = "boot recovery settings disabled";
        }

        if (!suspicious) return std::nullopt;

        nlohmann::json ctx;
        ctx["name"] = name;
        ctx["cmdline"] = cmdline;
        ctx["reason"] = reason;
        ctx["user_name"] = proc.value("user_name", "");
        ctx["pid"] = proc.value("pid", 0u);
        return make_match(ev, "Potential ransomware preparation command: " + reason, ctx);
    }
};

class SuspiciousShellRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "linux-suspicious-shell"; }
    std::string_view name() const noexcept override { return "Suspicious Shell Spawn"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 82; }
    std::vector<std::string> tags() const override {
        return {"execution", "linux", "defense-evasion", "sigma"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "process_start") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("process")) return std::nullopt;
        const auto& proc = payload.at("process");

        const std::string name = proc.value("name", "");
        const std::string exe = proc.value("exe", "");
        const std::string cmdline = proc.value("cmdline", "");

        static constexpr std::array SHELLS{"sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh"};
        const bool is_shell = std::any_of(
            SHELLS.begin(), SHELLS.end(), [&](const char* s) { return detail::contains_ci(name, s); });
        if (!is_shell) return std::nullopt;

        bool suspicious = false;
        std::string reason;

        if (detail::contains_any_ci(cmdline, {"base64 -d", "base64 --decode"})) {
            suspicious = true;
            reason = "base64 decode in shell command";
        } else if (detail::contains_any_ci(cmdline, {"/dev/tcp/", "nc ", "ncat ", "netcat "})) {
            suspicious = true;
            reason = "reverse-shell or netcat pattern";
        } else if (detail::contains_any_ci(cmdline, {"wget ", "curl "}) &&
                   detail::contains_any_ci(cmdline, {"| bash", "|bash", "| sh", "|sh"})) {
            suspicious = true;
            reason = "download-and-execute pattern";
        } else if (detail::contains_any_ci(cmdline, {"python -c", "python3 -c", "perl -e"})) {
            suspicious = true;
            reason = "one-liner interpreter execution";
        } else if (!exe.empty() && !detail::contains_any_ci(exe, {"/bin/", "/usr/bin/", "/usr/local/bin/", "/sbin/"})) {
            suspicious = true;
            reason = "shell launched from non-standard path";
        }

        if (!suspicious) return std::nullopt;

        nlohmann::json ctx;
        ctx["pid"] = proc.value("pid", 0u);
        ctx["ppid"] = proc.value("ppid", 0u);
        ctx["exe"] = exe;
        ctx["name"] = name;
        ctx["cmdline"] = cmdline;
        ctx["reason"] = reason;
        ctx["user_name"] = proc.value("user_name", "");

        return make_match(ev, "Suspicious shell command pattern: " + reason, ctx);
    }
};

class SqlInjectionToolExecutionRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "web-sqli-tool-execution"; }
    std::string_view name() const noexcept override { return "SQL Injection Tool/Pattern Execution"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 84; }
    std::vector<std::string> tags() const override {
        return {"initial-access", "sql-injection", "web", "execution"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "process_start") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("process")) return std::nullopt;
        const auto& proc = payload.at("process");

        const std::string name = proc.value("name", "");
        const std::string cmdline = proc.value("cmdline", "");

        bool matched = false;
        std::string reason;

        if (detail::contains_any_ci(name, {"sqlmap", "havij", "jsql"}) ||
            detail::contains_any_ci(cmdline, {"sqlmap", "--dbs", "--dump"})) {
            matched = true;
            reason = "SQLi tooling execution";
        } else if (detail::contains_any_ci(cmdline,
                                           {"union select", "or 1=1", "information_schema", "sleep(", "benchmark("})) {
            matched = true;
            reason = "SQL injection payload pattern in command line";
        }

        if (!matched) return std::nullopt;

        nlohmann::json ctx;
        ctx["name"] = name;
        ctx["cmdline"] = cmdline;
        ctx["reason"] = reason;
        ctx["pid"] = proc.value("pid", 0u);
        ctx["user_name"] = proc.value("user_name", "");

        return make_match(ev, "Potential SQL injection activity: " + reason, ctx);
    }
};

class PhishingFrameworkExecutionRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "phishing-framework-execution"; }
    std::string_view name() const noexcept override { return "Phishing Framework Execution"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 78; }
    std::vector<std::string> tags() const override {
        return {"phishing", "credential-access", "execution"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "process_start") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("process")) return std::nullopt;
        const auto& proc = payload.at("process");

        const std::string name = proc.value("name", "");
        const std::string cmdline = proc.value("cmdline", "");

        if (!detail::contains_any_ci(name, {"gophish", "evilginx", "setoolkit", "king-phisher"}) &&
            !detail::contains_any_ci(cmdline, {"gophish", "evilginx", "setoolkit", "king-phisher"})) {
            return std::nullopt;
        }

        nlohmann::json ctx;
        ctx["name"] = name;
        ctx["cmdline"] = cmdline;
        ctx["pid"] = proc.value("pid", 0u);
        ctx["user_name"] = proc.value("user_name", "");

        return make_match(ev, "Known phishing framework/process execution observed", ctx);
    }
};

class AuthBruteForceRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "auth-brute-force"; }
    std::string_view name() const noexcept override { return "Authentication Brute Force"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 80; }
    std::vector<std::string> tags() const override {
        return {"credential-access", "brute-force", "authentication"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "auth_failure") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("auth")) return std::nullopt;
        const auto& auth = payload.at("auth");

        const std::string user_name = auth.value("user_name", "");
        const std::string method = auth.value("method", "");
        const std::string src_ip = auth.value("src_ip", "");
        const std::string reason = auth.value("reason", "");
        const std::string bucket_key = ev.tenant_id + "|" + ev.host + "|" + user_name + "|" + src_ip + "|" + method;

        const auto now = std::chrono::system_clock::now();

        std::lock_guard<std::mutex> lock(mutex_);
        auto& bucket = buckets_[bucket_key];

        while (!bucket.attempts.empty() && (now - bucket.attempts.front()) > kWindow) {
            bucket.attempts.pop_front();
        }
        bucket.attempts.push_back(now);

        const std::size_t attempt_count = bucket.attempts.size();
        if (attempt_count < kThreshold) {
            return std::nullopt;
        }

        if (attempt_count != kThreshold && (attempt_count % kThreshold) != 0) {
            return std::nullopt;
        }

        nlohmann::json ctx;
        ctx["user_name"] = user_name;
        ctx["method"] = method;
        ctx["src_ip"] = src_ip;
        ctx["reason"] = reason;
        ctx["attempt_count"] = attempt_count;
        ctx["window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kWindow).count();
        ctx["host"] = ev.host;

        return make_match(
            ev,
            "Potential brute-force activity: " + std::to_string(attempt_count) + " auth failures within " +
                std::to_string(std::chrono::duration_cast<std::chrono::minutes>(kWindow).count()) +
                "m for user=" + user_name + " src=" + src_ip,
            ctx);
    }

private:
    struct Bucket {
        std::deque<std::chrono::system_clock::time_point> attempts;
    };

    static inline constexpr std::size_t kThreshold = 5;
    static inline constexpr auto kWindow = std::chrono::minutes(10);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, Bucket> buckets_;
};

class AuthPasswordSprayRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "auth-password-spray"; }
    std::string_view name() const noexcept override { return "Authentication Password Spray"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 82; }
    std::vector<std::string> tags() const override {
        return {"credential-access", "password-spray", "authentication"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "auth_failure") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("auth")) return std::nullopt;
        const auto& auth = payload.at("auth");

        const std::string user_name = auth.value("user_name", "");
        const std::string src_ip = auth.value("src_ip", "");
        const std::string method = auth.value("method", "");

        if (src_ip.empty() || user_name.empty()) return std::nullopt;

        const auto now = std::chrono::system_clock::now();
        const std::string key = ev.tenant_id + "|" + ev.host + "|" + src_ip + "|" + method;

        std::lock_guard<std::mutex> lock(mutex_);
        auto& bucket = buckets_[key];

        while (!bucket.attempts.empty() && (now - bucket.attempts.front().ts) > kWindow) {
            bucket.attempts.pop_front();
        }

        bucket.attempts.push_back(Attempt{now, user_name});

        std::unordered_set<std::string> uniq_users;
        for (const auto& a : bucket.attempts) {
            uniq_users.insert(a.user_name);
        }

        const std::size_t unique_count = uniq_users.size();
        if (unique_count < kDistinctUsersThreshold) return std::nullopt;
        if (unique_count <= bucket.last_fired_unique_count) return std::nullopt;

        bucket.last_fired_unique_count = unique_count;

        nlohmann::json ctx;
        ctx["src_ip"] = src_ip;
        ctx["method"] = method;
        ctx["attempt_count"] = bucket.attempts.size();
        ctx["unique_user_count"] = unique_count;
        ctx["window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kWindow).count();

        return make_match(
            ev,
            "Potential password spray from " + src_ip + " against " + std::to_string(unique_count) + " users",
            ctx);
    }

private:
    struct Attempt {
        std::chrono::system_clock::time_point ts;
        std::string user_name;
    };

    struct Bucket {
        std::deque<Attempt> attempts;
        std::size_t last_fired_unique_count{0};
    };

    static inline constexpr std::size_t kDistinctUsersThreshold = 6;
    static inline constexpr auto kWindow = std::chrono::minutes(10);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, Bucket> buckets_;
};

class NetworkPortScanRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "network-port-scan"; }
    std::string_view name() const noexcept override { return "Potential Port Scan"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 79; }
    std::vector<std::string> tags() const override {
        return {"discovery", "network", "port-scan"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "network_connect") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("network")) return std::nullopt;
        const auto& net = payload.at("network");

        const std::string direction = net.value("direction", "");
        if (direction != "outbound") return std::nullopt;

        const std::string src_ip = net.value("src_ip", "");
        const std::string dst_ip = net.value("dst_ip", "");
        const std::string protocol = net.value("protocol", "");
        const uint32_t dst_port = net.value<uint32_t>("dst_port", 0u);

        if (src_ip.empty() || dst_ip.empty() || dst_port == 0) return std::nullopt;

        const auto now = std::chrono::system_clock::now();
        const std::string key = ev.tenant_id + "|" + ev.host + "|" + src_ip + "|" + dst_ip + "|" + protocol;

        std::lock_guard<std::mutex> lock(mutex_);
        auto& bucket = buckets_[key];

        while (!bucket.probes.empty() && (now - bucket.probes.front().ts) > kWindow) {
            bucket.probes.pop_front();
        }
        bucket.probes.push_back(Probe{now, dst_port});

        std::unordered_set<uint32_t> unique_ports;
        for (const auto& p : bucket.probes) {
            unique_ports.insert(p.dst_port);
        }

        const std::size_t unique_port_count = unique_ports.size();
        if (unique_port_count < kUniquePortThreshold) return std::nullopt;
        if (unique_port_count <= bucket.last_fired_unique_port_count) return std::nullopt;

        bucket.last_fired_unique_port_count = unique_port_count;

        nlohmann::json ctx;
        ctx["src_ip"] = src_ip;
        ctx["dst_ip"] = dst_ip;
        ctx["protocol"] = protocol;
        ctx["unique_dst_ports"] = unique_port_count;
        ctx["connection_count"] = bucket.probes.size();
        ctx["window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kWindow).count();

        return make_match(
            ev,
            "Potential port scan: " + src_ip + " touched " + std::to_string(unique_port_count) +
                " ports on " + dst_ip,
            ctx);
    }

private:
    struct Probe {
        std::chrono::system_clock::time_point ts;
        uint32_t dst_port;
    };

    struct Bucket {
        std::deque<Probe> probes;
        std::size_t last_fired_unique_port_count{0};
    };

    static inline constexpr std::size_t kUniquePortThreshold = 12;
    static inline constexpr auto kWindow = std::chrono::minutes(3);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, Bucket> buckets_;
};

class NetworkC2BeaconRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "network-c2-beacon"; }
    std::string_view name() const noexcept override { return "Potential C2 Beaconing"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 77; }
    std::vector<std::string> tags() const override {
        return {"command-and-control", "beacon", "network"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "network_connect") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("network")) return std::nullopt;
        const auto& net = payload.at("network");

        const std::string direction = net.value("direction", "");
        if (direction != "outbound") return std::nullopt;

        const std::string src_ip = net.value("src_ip", "");
        const std::string dst_ip = net.value("dst_ip", "");
        const std::string protocol = net.value("protocol", "");
        const uint32_t dst_port = net.value<uint32_t>("dst_port", 0u);

        if (src_ip.empty() || dst_ip.empty() || dst_port == 0) return std::nullopt;

        const std::string proc_key = detail::fallback_process_key(net, ev);
        const std::string key =
            ev.tenant_id + "|" + ev.host + "|" + proc_key + "|" + src_ip + "|" + dst_ip + "|" +
            std::to_string(dst_port) + "|" + protocol;

        const auto now = std::chrono::system_clock::now();

        std::lock_guard<std::mutex> lock(mutex_);
        auto& bucket = buckets_[key];
        while (!bucket.hits.empty() && (now - bucket.hits.front()) > kWindow) {
            bucket.hits.pop_front();
        }
        bucket.hits.push_back(now);

        const std::size_t count = bucket.hits.size();
        if (count < kThreshold) return std::nullopt;
        if (count != kThreshold && (count % kThreshold) != 0) return std::nullopt;

        nlohmann::json ctx;
        ctx["src_ip"] = src_ip;
        ctx["dst_ip"] = dst_ip;
        ctx["dst_port"] = dst_port;
        ctx["protocol"] = protocol;
        ctx["process_key"] = proc_key;
        ctx["connection_count"] = count;
        ctx["window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kWindow).count();

        return make_match(
            ev,
            "Potential C2 beaconing: repeated outbound connections to " + dst_ip + ":" +
                std::to_string(dst_port),
            ctx);
    }

private:
    struct Bucket {
        std::deque<std::chrono::system_clock::time_point> hits;
    };

    static inline constexpr std::size_t kThreshold = 20;
    static inline constexpr auto kWindow = std::chrono::minutes(5);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, Bucket> buckets_;
};

class NetworkDdosFloodRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "network-ddos-flood"; }
    std::string_view name() const noexcept override { return "Potential DDoS/Flood Traffic"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 76; }
    std::vector<std::string> tags() const override {
        return {"impact", "ddos", "network"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "network_connect") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("network")) return std::nullopt;
        const auto& net = payload.at("network");

        const std::string direction = net.value("direction", "");
        if (direction != "outbound") return std::nullopt;

        const std::string src_ip = net.value("src_ip", "");
        const std::string dst_ip = net.value("dst_ip", "");
        const std::string protocol = net.value("protocol", "");
        const uint32_t dst_port = net.value<uint32_t>("dst_port", 0u);

        if (src_ip.empty() || dst_ip.empty() || dst_port == 0) return std::nullopt;

        const std::string key =
            ev.tenant_id + "|" + ev.host + "|" + src_ip + "|" + dst_ip + "|" + std::to_string(dst_port) +
            "|" + protocol;
        const auto now = std::chrono::system_clock::now();

        std::lock_guard<std::mutex> lock(mutex_);
        auto& bucket = buckets_[key];
        while (!bucket.hits.empty() && (now - bucket.hits.front()) > kWindow) {
            bucket.hits.pop_front();
        }
        bucket.hits.push_back(now);

        const std::size_t count = bucket.hits.size();
        if (count < kThreshold) return std::nullopt;
        if (count != kThreshold && (count % kThreshold) != 0) return std::nullopt;

        nlohmann::json ctx;
        ctx["src_ip"] = src_ip;
        ctx["dst_ip"] = dst_ip;
        ctx["dst_port"] = dst_port;
        ctx["protocol"] = protocol;
        ctx["connection_count"] = count;
        ctx["window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kWindow).count();

        return make_match(
            ev,
            "Potential flood traffic: " + std::to_string(count) + " outbound connections within short window",
            ctx);
    }

private:
    struct Bucket {
        std::deque<std::chrono::system_clock::time_point> hits;
    };

    static inline constexpr std::size_t kThreshold = 120;
    static inline constexpr auto kWindow = std::chrono::seconds(30);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, Bucket> buckets_;
};

class CorrelatedExecutionToRarePortRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "correlation-execution-to-rare-port"; }
    std::string_view name() const noexcept override { return "Correlated Suspicious Execution Followed by Rare Port Egress"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 88; }
    std::vector<std::string> tags() const override {
        return {"correlation", "multi-stage", "command-and-control", "execution", "network"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        const auto now = std::chrono::system_clock::now();

        if (ev.event_type == "process_start") {
            const auto& payload = ev.doc.at("event");
            if (!payload.contains("process")) return std::nullopt;
            const auto& proc = payload.at("process");

            const std::string process_guid = ev.process_guid;
            if (process_guid.empty()) return std::nullopt;

            std::string reason;
            if (!detail::suspicious_execution_signal(proc, reason)) return std::nullopt;

            const std::string key = ev.tenant_id + "|" + ev.host + "|" + process_guid;

            std::lock_guard<std::mutex> lock(mutex_);
            cleanup_locked(now);
            suspicious_processes_[key] = Signal{
                now,
                reason,
                proc.value("cmdline", ""),
                proc.value("exe", "")
            };
            return std::nullopt;
        }

        if (ev.event_type != "network_connect") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("network")) return std::nullopt;
        const auto& net = payload.at("network");

        if (net.value("direction", "") != "outbound") return std::nullopt;

        const uint32_t dst_port = net.value<uint32_t>("dst_port", 0u);
        if (dst_port == 0 || detail::is_common_benign_port(dst_port)) return std::nullopt;

        const std::string process_guid = net.value("process_guid", ev.process_guid);
        if (process_guid.empty()) return std::nullopt;

        const std::string key = ev.tenant_id + "|" + ev.host + "|" + process_guid;

        std::lock_guard<std::mutex> lock(mutex_);
        cleanup_locked(now);

        const auto signal_it = suspicious_processes_.find(key);
        if (signal_it == suspicious_processes_.end()) return std::nullopt;

        const auto cool_it = last_alert_at_.find(key);
        if (cool_it != last_alert_at_.end() && (now - cool_it->second) < kAlertCooldown) {
            return std::nullopt;
        }

        last_alert_at_[key] = now;

        nlohmann::json ctx;
        ctx["process_guid"] = process_guid;
        ctx["stage1_reason"] = signal_it->second.reason;
        ctx["stage1_cmdline"] = signal_it->second.cmdline;
        ctx["stage1_exe"] = signal_it->second.exe;
        ctx["dst_ip"] = net.value("dst_ip", "");
        ctx["dst_port"] = dst_port;
        ctx["src_ip"] = net.value("src_ip", "");
        ctx["protocol"] = net.value("protocol", "");
        ctx["window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kWindow).count();

        return make_match(
            ev,
            "Suspicious execution followed by outbound rare-port connection (possible staged C2)",
            ctx);
    }

private:
    struct Signal {
        std::chrono::system_clock::time_point ts;
        std::string reason;
        std::string cmdline;
        std::string exe;
    };

    void cleanup_locked(std::chrono::system_clock::time_point now) const {
        for (auto it = suspicious_processes_.begin(); it != suspicious_processes_.end();) {
            if ((now - it->second.ts) > kWindow) {
                it = suspicious_processes_.erase(it);
            } else {
                ++it;
            }
        }
        for (auto it = last_alert_at_.begin(); it != last_alert_at_.end();) {
            if ((now - it->second) > kWindow) {
                it = last_alert_at_.erase(it);
            } else {
                ++it;
            }
        }
    }

    static inline constexpr auto kWindow = std::chrono::minutes(10);
    static inline constexpr auto kAlertCooldown = std::chrono::minutes(2);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, Signal> suspicious_processes_;
    mutable std::unordered_map<std::string, std::chrono::system_clock::time_point> last_alert_at_;
};

class CorrelatedAuthToSensitiveFileRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "correlation-auth-to-sensitive-file"; }
    std::string_view name() const noexcept override { return "Correlated Auth Failures Followed by Sensitive File Access"; }
    Severity severity() const noexcept override { return Severity::Critical; }
    uint32_t risk_score() const noexcept override { return 92; }
    std::vector<std::string> tags() const override {
        return {"correlation", "multi-stage", "credential-access", "collection", "file"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        const auto now = std::chrono::system_clock::now();

        if (ev.event_type == "auth_failure") {
            const auto& payload = ev.doc.at("event");
            if (!payload.contains("auth")) return std::nullopt;
            const auto& auth = payload.at("auth");

            const std::string user_name = auth.value("user_name", "");
            if (user_name.empty()) return std::nullopt;

            const std::string key = ev.tenant_id + "|" + ev.host + "|" + user_name;

            std::lock_guard<std::mutex> lock(mutex_);
            cleanup_locked(now);
            auto& state = user_state_[key];

            while (!state.auth_failures.empty() && (now - state.auth_failures.front()) > kAuthWindow) {
                state.auth_failures.pop_front();
            }
            state.auth_failures.push_back(now);

            if (state.auth_failures.size() >= kAuthThreshold) {
                state.suspected_since = now;
            }
            return std::nullopt;
        }

        if (ev.event_type != "file_open") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("file")) return std::nullopt;
        const auto& file = payload.at("file");

        const std::string path = file.value("path", "");
        const std::string result = file.value("result", "");
        const std::string user_name = file.value("user_name", ev.user_name);

        if (user_name.empty() || path.empty()) return std::nullopt;
        if (!detail::contains_ci(result, "success") || !detail::is_sensitive_file(path)) return std::nullopt;

        const std::string key = ev.tenant_id + "|" + ev.host + "|" + user_name;

        std::lock_guard<std::mutex> lock(mutex_);
        cleanup_locked(now);

        const auto it = user_state_.find(key);
        if (it == user_state_.end()) return std::nullopt;
        if (it->second.suspected_since.time_since_epoch().count() == 0) return std::nullopt;
        if ((now - it->second.suspected_since) > kCorrelationWindow) return std::nullopt;
        if (it->second.last_alert.time_since_epoch().count() != 0 &&
            (now - it->second.last_alert) < kAlertCooldown) {
            return std::nullopt;
        }

        it->second.last_alert = now;

        nlohmann::json ctx;
        ctx["user_name"] = user_name;
        ctx["path"] = path;
        ctx["auth_failure_count"] = it->second.auth_failures.size();
        ctx["auth_window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kAuthWindow).count();
        ctx["correlation_window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kCorrelationWindow).count();

        return make_match(
            ev,
            "Sensitive file access observed shortly after repeated authentication failures",
            ctx);
    }

private:
    struct UserState {
        std::deque<std::chrono::system_clock::time_point> auth_failures;
        std::chrono::system_clock::time_point suspected_since{};
        std::chrono::system_clock::time_point last_alert{};
    };

    void cleanup_locked(std::chrono::system_clock::time_point now) const {
        for (auto it = user_state_.begin(); it != user_state_.end();) {
            while (!it->second.auth_failures.empty() && (now - it->second.auth_failures.front()) > kCorrelationWindow) {
                it->second.auth_failures.pop_front();
            }

            const bool stale_suspect =
                it->second.suspected_since.time_since_epoch().count() != 0 &&
                (now - it->second.suspected_since) > kCorrelationWindow;
            if (stale_suspect) {
                it->second.suspected_since = std::chrono::system_clock::time_point{};
            }

            const bool has_signal = !it->second.auth_failures.empty() ||
                                    it->second.suspected_since.time_since_epoch().count() != 0;
            if (!has_signal) {
                it = user_state_.erase(it);
            } else {
                ++it;
            }
        }
    }

    static inline constexpr std::size_t kAuthThreshold = 5;
    static inline constexpr auto kAuthWindow = std::chrono::minutes(10);
    static inline constexpr auto kCorrelationWindow = std::chrono::minutes(15);
    static inline constexpr auto kAlertCooldown = std::chrono::minutes(3);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, UserState> user_state_;
};

class CorrelatedAuthProcessRarePortRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "correlation-auth-process-rare-port"; }
    std::string_view name() const noexcept override {
        return "Correlated Auth Failures -> Suspicious Process -> Rare Port Egress";
    }
    Severity severity() const noexcept override { return Severity::Critical; }
    uint32_t risk_score() const noexcept override { return 95; }
    std::vector<std::string> tags() const override {
        return {"correlation", "multi-stage", "credential-access", "execution", "command-and-control"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        const auto now = std::chrono::system_clock::now();

        if (ev.event_type == "auth_failure") {
            const auto& payload = ev.doc.at("event");
            if (!payload.contains("auth")) return std::nullopt;
            const auto& auth = payload.at("auth");

            const std::string user_name = auth.value("user_name", "");
            if (user_name.empty()) return std::nullopt;

            const std::string key = ev.tenant_id + "|" + ev.host + "|" + user_name;

            std::lock_guard<std::mutex> lock(mutex_);
            cleanup_locked(now);
            auto& state = user_state_[key];
            while (!state.auth_failures.empty() && (now - state.auth_failures.front()) > kAuthWindow) {
                state.auth_failures.pop_front();
            }
            state.auth_failures.push_back(now);
            if (state.auth_failures.size() >= kAuthThreshold) {
                state.suspected_since = now;
            }
            return std::nullopt;
        }

        if (ev.event_type == "process_start") {
            const auto& payload = ev.doc.at("event");
            if (!payload.contains("process")) return std::nullopt;
            const auto& proc = payload.at("process");

            const std::string process_guid = ev.process_guid;
            const std::string user_name = proc.value("user_name", ev.user_name);
            if (process_guid.empty() || user_name.empty()) return std::nullopt;

            std::string exec_reason;
            if (!detail::suspicious_execution_signal(proc, exec_reason)) return std::nullopt;

            const std::string user_key = ev.tenant_id + "|" + ev.host + "|" + user_name;
            const std::string process_key = ev.tenant_id + "|" + ev.host + "|" + process_guid;

            std::lock_guard<std::mutex> lock(mutex_);
            cleanup_locked(now);

            const auto user_it = user_state_.find(user_key);
            if (user_it == user_state_.end()) return std::nullopt;
            if (user_it->second.suspected_since.time_since_epoch().count() == 0) return std::nullopt;
            if ((now - user_it->second.suspected_since) > kUserCorrelationWindow) return std::nullopt;

            staged_processes_[process_key] = ProcessStage{
                now,
                user_name,
                exec_reason,
                proc.value("cmdline", ""),
                user_it->second.auth_failures.size()
            };
            return std::nullopt;
        }

        if (ev.event_type != "network_connect") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("network")) return std::nullopt;
        const auto& net = payload.at("network");

        if (net.value("direction", "") != "outbound") return std::nullopt;

        const uint32_t dst_port = net.value<uint32_t>("dst_port", 0u);
        if (dst_port == 0 || detail::is_common_benign_port(dst_port)) return std::nullopt;

        const std::string process_guid = net.value("process_guid", ev.process_guid);
        if (process_guid.empty()) return std::nullopt;

        const std::string process_key = ev.tenant_id + "|" + ev.host + "|" + process_guid;

        std::lock_guard<std::mutex> lock(mutex_);
        cleanup_locked(now);

        const auto stage_it = staged_processes_.find(process_key);
        if (stage_it == staged_processes_.end()) return std::nullopt;
        if ((now - stage_it->second.ts) > kProcessCorrelationWindow) return std::nullopt;

        const auto cooldown_it = last_alert_at_.find(process_key);
        if (cooldown_it != last_alert_at_.end() && (now - cooldown_it->second) < kAlertCooldown) {
            return std::nullopt;
        }

        last_alert_at_[process_key] = now;

        nlohmann::json ctx;
        ctx["user_name"] = stage_it->second.user_name;
        ctx["process_guid"] = process_guid;
        ctx["stage1_auth_failure_count"] = stage_it->second.auth_failure_count;
        ctx["stage2_reason"] = stage_it->second.exec_reason;
        ctx["stage2_cmdline"] = stage_it->second.cmdline;
        ctx["dst_ip"] = net.value("dst_ip", "");
        ctx["dst_port"] = dst_port;
        ctx["src_ip"] = net.value("src_ip", "");
        ctx["protocol"] = net.value("protocol", "");
        ctx["auth_window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kAuthWindow).count();
        ctx["process_window_seconds"] = std::chrono::duration_cast<std::chrono::seconds>(kProcessCorrelationWindow).count();

        return make_match(
            ev,
            "Multi-stage chain detected: auth failures followed by suspicious execution and rare-port egress",
            ctx);
    }

private:
    struct UserState {
        std::deque<std::chrono::system_clock::time_point> auth_failures;
        std::chrono::system_clock::time_point suspected_since{};
    };

    struct ProcessStage {
        std::chrono::system_clock::time_point ts;
        std::string user_name;
        std::string exec_reason;
        std::string cmdline;
        std::size_t auth_failure_count{0};
    };

    void cleanup_locked(std::chrono::system_clock::time_point now) const {
        for (auto it = user_state_.begin(); it != user_state_.end();) {
            while (!it->second.auth_failures.empty() && (now - it->second.auth_failures.front()) > kUserCorrelationWindow) {
                it->second.auth_failures.pop_front();
            }
            if (it->second.suspected_since.time_since_epoch().count() != 0 &&
                (now - it->second.suspected_since) > kUserCorrelationWindow) {
                it->second.suspected_since = std::chrono::system_clock::time_point{};
            }

            const bool active = !it->second.auth_failures.empty() ||
                                it->second.suspected_since.time_since_epoch().count() != 0;
            if (!active) {
                it = user_state_.erase(it);
            } else {
                ++it;
            }
        }

        for (auto it = staged_processes_.begin(); it != staged_processes_.end();) {
            if ((now - it->second.ts) > kProcessCorrelationWindow) {
                it = staged_processes_.erase(it);
            } else {
                ++it;
            }
        }

        for (auto it = last_alert_at_.begin(); it != last_alert_at_.end();) {
            if ((now - it->second) > kUserCorrelationWindow) {
                it = last_alert_at_.erase(it);
            } else {
                ++it;
            }
        }
    }

    static inline constexpr std::size_t kAuthThreshold = 5;
    static inline constexpr auto kAuthWindow = std::chrono::minutes(10);
    static inline constexpr auto kUserCorrelationWindow = std::chrono::minutes(20);
    static inline constexpr auto kProcessCorrelationWindow = std::chrono::minutes(10);
    static inline constexpr auto kAlertCooldown = std::chrono::minutes(3);

    mutable std::mutex mutex_;
    mutable std::unordered_map<std::string, UserState> user_state_;
    mutable std::unordered_map<std::string, ProcessStage> staged_processes_;
    mutable std::unordered_map<std::string, std::chrono::system_clock::time_point> last_alert_at_;
};

class NetworkRarePortRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "network-rare-port"; }
    std::string_view name() const noexcept override { return "Outbound Connection to Rare Port"; }
    Severity severity() const noexcept override { return Severity::Medium; }
    uint32_t risk_score() const noexcept override { return 60; }
    std::vector<std::string> tags() const override {
        return {"command-and-control", "exfiltration", "network"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "network_connect") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("network")) return std::nullopt;
        const auto& net = payload.at("network");

        const std::string direction = net.value("direction", "");
        if (direction != "outbound") return std::nullopt;

        const uint32_t dst_port = net.value<uint32_t>("dst_port", 0u);
        if (dst_port == 0) return std::nullopt;

        if (detail::is_common_benign_port(dst_port)) return std::nullopt;

        nlohmann::json ctx;
        ctx["src_ip"] = net.value("src_ip", "");
        ctx["dst_ip"] = net.value("dst_ip", "");
        ctx["dst_port"] = dst_port;
        ctx["protocol"] = net.value("protocol", "");
        ctx["pid"] = net.value("pid", 0u);

        return make_match(
            ev,
            "Outbound connection to rare port " + std::to_string(dst_port) + " dst=" +
                net.value("dst_ip", std::string()),
            ctx);
    }
};

class SensitiveFileAccessRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "sensitive-file-access"; }
    std::string_view name() const noexcept override { return "Sensitive File Access"; }
    Severity severity() const noexcept override { return Severity::High; }
    uint32_t risk_score() const noexcept override { return 86; }
    std::vector<std::string> tags() const override {
        return {"credential-access", "collection", "file"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "file_open") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("file")) return std::nullopt;
        const auto& file = payload.at("file");

        const std::string path = file.value("path", "");
        const std::string result = file.value("result", "");

        if (path.empty()) return std::nullopt;
        if (!detail::contains_ci(result, "success")) return std::nullopt;
        if (!detail::is_sensitive_file(path)) return std::nullopt;

        nlohmann::json ctx;
        ctx["path"] = path;
        ctx["result"] = result;
        ctx["pid"] = file.value("pid", 0u);
        ctx["process_guid"] = file.value("process_guid", "");
        ctx["user_name"] = file.value("user_name", "");
        ctx["flags"] = file.value("flags", nlohmann::json::array());

        return make_match(ev, "Sensitive file was accessed successfully: " + path, ctx);
    }
};

class SuspiciousTempFileDropRule final : public BaseRule {
public:
    std::string_view id() const noexcept override { return "suspicious-temp-file-drop"; }
    std::string_view name() const noexcept override { return "Suspicious Temp File Drop"; }
    Severity severity() const noexcept override { return Severity::Medium; }
    uint32_t risk_score() const noexcept override { return 68; }
    std::vector<std::string> tags() const override {
        return {"defense-evasion", "malware", "file"};
    }

    std::optional<RuleMatch> evaluate(const ParsedEvent& ev) const override {
        if (ev.event_type != "file_open") return std::nullopt;

        const auto& payload = ev.doc.at("event");
        if (!payload.contains("file")) return std::nullopt;
        const auto& file = payload.at("file");

        const std::string path = file.value("path", "");
        const std::string result = file.value("result", "");

        if (path.empty() || !detail::contains_ci(result, "success")) return std::nullopt;
        if (!detail::is_temp_like_path(path)) return std::nullopt;

        const auto flags = file.value("flags", nlohmann::json::array());
        if (!detail::has_write_flag(flags)) return std::nullopt;

        const bool risky_extension = detail::ends_with_ci(path, ".exe") || detail::ends_with_ci(path, ".dll") ||
                                     detail::ends_with_ci(path, ".ps1") || detail::ends_with_ci(path, ".bat") ||
                                     detail::ends_with_ci(path, ".vbs") || detail::ends_with_ci(path, ".js") ||
                                     detail::ends_with_ci(path, ".sh") || detail::ends_with_ci(path, ".py") ||
                                     detail::ends_with_ci(path, ".php");

        if (!risky_extension) return std::nullopt;

        nlohmann::json ctx;
        ctx["path"] = path;
        ctx["flags"] = flags;
        ctx["result"] = result;
        ctx["pid"] = file.value("pid", 0u);
        ctx["process_guid"] = file.value("process_guid", "");
        ctx["user_name"] = file.value("user_name", "");

        return make_match(ev, "Executable/script written to temp-like path: " + path, ctx);
    }
};

}  // namespace aegis::detection
