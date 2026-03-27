#include "JavaNumberFormat.h"

#include <array>
#include <charconv>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace {

std::string trimFixedLikeJava(std::string s) {
    const std::size_t dot = s.find('.');
    if (dot == std::string::npos) {
        return s + ".0";
    }

    while (!s.empty() && s.back() == '0') {
        s.pop_back();
    }
    if (!s.empty() && s.back() == '.') {
        s.push_back('0');
    }
    return s;
}

std::string normalizeExponentJavaStyle(std::string s) {
    std::size_t epos = s.find('e');
    if (epos == std::string::npos) {
        epos = s.find('E');
    }
    if (epos == std::string::npos) {
        return s;
    }

    std::string mant = s.substr(0, epos);
    std::string exp = s.substr(epos + 1);

    char sign = 0;
    if (!exp.empty() && (exp[0] == '+' || exp[0] == '-')) {
        sign = exp[0];
        exp.erase(0, 1);
    }

    while (exp.size() > 1 && exp[0] == '0') {
        exp.erase(0, 1);
    }

    std::string out = mant + "E";
    if (sign == '-') {
        out += '-';
    }
    out += exp;
    return out;
}

std::string scientificToPlain(std::string s) {
    std::size_t epos = s.find('E');
    if (epos == std::string::npos) {
        epos = s.find('e');
    }
    if (epos == std::string::npos) {
        return s;
    }

    std::string mant = s.substr(0, epos);
    std::string exp_str = s.substr(epos + 1);

    bool neg = false;
    if (!mant.empty() && mant[0] == '-') {
        neg = true;
        mant.erase(0, 1);
    } else if (!mant.empty() && mant[0] == '+') {
        mant.erase(0, 1);
    }

    int exp = 0;
    int sign = 1;
    std::size_t pos = 0;
    if (pos < exp_str.size() && (exp_str[pos] == '+' || exp_str[pos] == '-')) {
        sign = (exp_str[pos] == '-') ? -1 : 1;
        ++pos;
    }
    for (; pos < exp_str.size(); ++pos) {
        const char c = exp_str[pos];
        if (c < '0' || c > '9') {
            break;
        }
        exp = exp * 10 + (c - '0');
    }
    exp *= sign;

    std::string digits;
    int digits_before_dot = 0;
    const std::size_t dot = mant.find('.');
    if (dot == std::string::npos) {
        digits = mant;
        digits_before_dot = static_cast<int>(digits.size());
    } else {
        digits = mant.substr(0, dot) + mant.substr(dot + 1);
        digits_before_dot = static_cast<int>(dot);
    }

    if (digits.empty()) {
        return neg ? "-0.0" : "0.0";
    }

    int decimal_index = digits_before_dot + exp;
    std::string out;
    if (decimal_index <= 0) {
        out = "0.";
        out.append(static_cast<std::size_t>(-decimal_index), '0');
        out += digits;
    } else if (decimal_index >= static_cast<int>(digits.size())) {
        out = digits;
        out.append(static_cast<std::size_t>(decimal_index - static_cast<int>(digits.size())), '0');
    } else {
        out = digits.substr(0, static_cast<std::size_t>(decimal_index));
        out += '.';
        out += digits.substr(static_cast<std::size_t>(decimal_index));
    }

    out = trimFixedLikeJava(out);
    if (neg && out != "0.0") {
        out.insert(out.begin(), '-');
    }
    return out;
}

}  // namespace

namespace javafmt {

std::string formatJavaLikeDouble(double value) {
    if (std::isnan(value)) {
        return "NaN";
    }
    if (std::isinf(value)) {
        return value > 0 ? "Infinity" : "-Infinity";
    }

    std::array<char, 128> buffer{};
    std::string out;
    auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value, std::chars_format::general);
    if (result.ec == std::errc()) {
        out.assign(buffer.data(), result.ptr);
    } else {
        std::ostringstream oss;
        oss.setf(std::ios::fmtflags(0), std::ios::floatfield);
        oss.precision(17);
        oss << value;
        out = oss.str();
    }

    const double abs_value = std::fabs(value);
    const bool use_plain = (abs_value == 0.0) || (abs_value >= 1e-3 && abs_value < 1e7);
    if (use_plain && (out.find('e') != std::string::npos || out.find('E') != std::string::npos)) {
        out = scientificToPlain(out);
    } else {
        out = normalizeExponentJavaStyle(out);
    }

    // Java-style CSV often shows whole-number doubles as x.0.
    if (out.find('.') == std::string::npos && out.find('e') == std::string::npos && out.find('E') == std::string::npos) {
        out += ".0";
    }

    return out;
}

}  // namespace javafmt
