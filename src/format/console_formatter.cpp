#include "semantics_av/format/console_formatter.hpp"
#include "semantics_av/format/format_utils.hpp"
#include "semantics_av/format/markdown_renderer.hpp"
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <wchar.h>
#include <cstring>

namespace semantics_av {
namespace format {

TableRenderer::TableRenderer(bool use_colors) : use_colors_(use_colors) {
    setlocale(LC_ALL, "");
}

void TableRenderer::addRow(const TableRow& row) {
    rows_.push_back(row);
}

std::string TableRenderer::render() {
    if (rows_.empty()) return "";
    
    calculateColumnWidths();
    
    std::ostringstream output;
    
    for (size_t row_idx = 0; row_idx < rows_.size(); ++row_idx) {
        const auto& row = rows_[row_idx];
        
        if (row_idx == 0) {
            output << renderBorder(true, false, row.is_header);
        }
        
        std::vector<std::vector<std::string>> wrapped_cells;
        size_t max_lines = 0;
        
        for (size_t col_idx = 0; col_idx < row.cells.size(); ++col_idx) {
            auto lines = wrapText(row.cells[col_idx].content, column_widths_[col_idx]);
            max_lines = std::max(max_lines, lines.size());
            wrapped_cells.push_back(lines);
        }
        
        for (size_t line_idx = 0; line_idx < max_lines; ++line_idx) {
            output << box_.vertical;
            for (size_t col_idx = 0; col_idx < row.cells.size(); ++col_idx) {
                output << renderCell(row.cells[col_idx], column_widths_[col_idx], 
                                    wrapped_cells[col_idx], line_idx);
                output << box_.vertical;
            }
            output << "\n";
        }
        
        if (row.has_heavy_bottom_border) {
            output << renderBorder(false, true, true);
        } else if (row.has_bottom_border || row_idx == rows_.size() - 1) {
            output << renderBorder(false, true, false);
        }
    }
    
    return output.str();
}

void TableRenderer::calculateColumnWidths() {
    if (rows_.empty()) return;
    
    size_t num_cols = rows_[0].cells.size();
    column_widths_.resize(num_cols, 0);
    
    for (const auto& row : rows_) {
        for (size_t i = 0; i < row.cells.size() && i < num_cols; ++i) {
            const auto& cell = row.cells[i];
            int content_width = getDisplayWidth(cell.content);
            
            if (cell.max_width > 0) {
                column_widths_[i] = std::max(column_widths_[i], std::min(content_width, cell.max_width));
            } else {
                column_widths_[i] = std::max(column_widths_[i], content_width);
            }
            
            if (cell.min_width > 0) {
                column_widths_[i] = std::max(column_widths_[i], cell.min_width);
            }
        }
    }
}

std::vector<std::string> TableRenderer::wrapText(const std::string& text, int width) {
    std::vector<std::string> lines;
    if (text.empty() || width <= 0) {
        lines.push_back("");
        return lines;
    }
    
    std::string current_line;
    std::istringstream words(text);
    std::string word;
    
    while (words >> word) {
        if (current_line.empty()) {
            int word_width = getDisplayWidth(word);
            if (word_width > width) {
                size_t i = 0;
                while (i < word.length()) {
                    std::string chunk = extractChunk(word, i, width);
                    lines.push_back(chunk);
                }
            } else {
                current_line = word;
            }
        } else {
            int current_width = getDisplayWidth(current_line);
            int word_width = getDisplayWidth(word);
            if (current_width + 1 + word_width <= width) {
                current_line += " " + word;
            } else {
                lines.push_back(current_line);
                int word_width_check = getDisplayWidth(word);
                if (word_width_check > width) {
                    size_t i = 0;
                    while (i < word.length()) {
                        std::string chunk = extractChunk(word, i, width);
                        lines.push_back(chunk);
                    }
                    current_line.clear();
                } else {
                    current_line = word;
                }
            }
        }
    }
    
    if (!current_line.empty()) {
        lines.push_back(current_line);
    }
    
    if (lines.empty()) {
        lines.push_back("");
    }
    
    return lines;
}

std::string TableRenderer::extractChunk(const std::string& text, size_t& pos, int max_width) {
    std::string chunk;
    int accumulated_width = 0;
    std::mbstate_t state = std::mbstate_t();
    
    const char* ptr = text.c_str() + pos;
    const char* end = text.c_str() + text.length();
    const char* start = ptr;
    
    while (ptr < end && accumulated_width < max_width) {
        wchar_t wc;
        size_t len = std::mbrtowc(&wc, ptr, end - ptr, &state);
        
        if (len == 0 || len == static_cast<size_t>(-1) || len == static_cast<size_t>(-2)) {
            ptr++;
            accumulated_width++;
        } else {
            int char_width = wcwidth(wc);
            if (char_width < 0) char_width = 1;
            
            if (accumulated_width + char_width > max_width) {
                break;
            }
            
            accumulated_width += char_width;
            ptr += len;
        }
    }
    
    size_t consumed = ptr - start;
    chunk = text.substr(pos, consumed);
    pos += consumed;
    
    return chunk;
}

std::string TableRenderer::renderCell(const TableCell& cell, int width, 
                                       const std::vector<std::string>& lines, size_t line_index) {
    std::string content;
    if (line_index < lines.size()) {
        content = lines[line_index];
    }
    
    int content_width = getDisplayWidth(content);
    int padding = width - content_width;
    if (padding < 0) padding = 0;
    
    std::string result = " " + content + std::string(padding + 1, ' ');
    
    return applyStyle(result, cell.style);
}

std::string TableRenderer::repeatString(const std::string& str, int count) {
    std::string result;
    result.reserve(str.length() * count);
    for (int i = 0; i < count; ++i) {
        result += str;
    }
    return result;
}

std::string TableRenderer::renderBorder(bool is_top, bool is_bottom, bool is_heavy) {
    std::ostringstream border;
    
    if (is_heavy) {
        if (is_top) {
            border << box_.heavy_top_left;
            for (size_t i = 0; i < column_widths_.size(); ++i) {
                border << repeatString(box_.heavy_horizontal, column_widths_[i] + 2);
                if (i < column_widths_.size() - 1) {
                    border << box_.t_down;
                }
            }
            border << box_.heavy_top_right;
        } else {
            border << box_.heavy_bottom_left;
            for (size_t i = 0; i < column_widths_.size(); ++i) {
                border << repeatString(box_.heavy_horizontal, column_widths_[i] + 2);
                if (i < column_widths_.size() - 1) {
                    border << box_.t_up;
                }
            }
            border << box_.heavy_bottom_right;
        }
    } else {
        if (is_top) {
            border << box_.top_left;
            for (size_t i = 0; i < column_widths_.size(); ++i) {
                border << repeatString(box_.horizontal, column_widths_[i] + 2);
                if (i < column_widths_.size() - 1) {
                    border << box_.t_down;
                }
            }
            border << box_.top_right;
        } else {
            border << box_.bottom_left;
            for (size_t i = 0; i < column_widths_.size(); ++i) {
                border << repeatString(box_.horizontal, column_widths_[i] + 2);
                if (i < column_widths_.size() - 1) {
                    border << box_.t_up;
                }
            }
            border << box_.bottom_right;
        }
    }
    
    border << "\n";
    return border.str();
}

std::string TableRenderer::applyStyle(const std::string& text, const CellStyle& style) {
    if (!use_colors_) return text;
    
    std::string result = text;
    
    if (!style.bg_color.empty()) {
        result = style.bg_color + result + "\033[0m";
    }
    
    if (!style.fg_color.empty()) {
        result = style.fg_color + result + "\033[0m";
    }
    
    if (style.bold) {
        result = "\033[1m" + result + "\033[0m";
    }
    
    return result;
}

std::string TableRenderer::colorize(const std::string& text, const std::string& color_code) {
    if (!use_colors_ || color_code.empty()) return text;
    return color_code + text + "\033[0m";
}

int TableRenderer::getDisplayWidth(const std::string& text) {
    int width = 0;
    bool in_escape = false;
    
    std::mbstate_t state = std::mbstate_t();
    const char* ptr = text.c_str();
    const char* end = ptr + text.length();
    
    while (ptr < end) {
        if (*ptr == '\033') {
            in_escape = true;
            ptr++;
        } else if (in_escape && *ptr == 'm') {
            in_escape = false;
            ptr++;
        } else if (!in_escape) {
            wchar_t wc;
            size_t len = std::mbrtowc(&wc, ptr, end - ptr, &state);
            
            if (len == 0 || len == static_cast<size_t>(-1) || len == static_cast<size_t>(-2)) {
                ptr++;
                width++;
            } else {
                int char_width = wcwidth(wc);
                width += (char_width > 0) ? char_width : 1;
                ptr += len;
            }
        } else {
            ptr++;
        }
    }
    
    return width;
}

ConsoleFormatter::ConsoleFormatter(bool use_colors) 
    : use_colors_(use_colors && isatty(STDOUT_FILENO)) {}

void ConsoleFormatter::format(const network::AnalysisResult& result, std::ostream& out) {
    formatDetectionSummary(result, out);
    
    if (result.intelligence.statistics.processed_samples > 0) {
        out << "\n";
        formatIntelligenceStatistics(result, out);
    }
    
    if (!result.intelligence.similar_samples.empty()) {
        out << "\n";
        formatAttributeComparison(result, out);
    }
    
    if (!result.natural_language_report.empty()) {
        out << "\n";
        formatNaturalLanguageReport(result, out);
    }
}

void ConsoleFormatter::formatLegend(const network::AnalysisResult& result, std::ostream& out) {
    bool is_confirmed = hasGroundTruthLabel(result.tags);
    
    bool show_confirmed_legend = is_confirmed;
    bool show_predicted_legend = !is_confirmed;
    bool show_legend = show_confirmed_legend || show_predicted_legend;
    
    if (show_legend) {
        out << colorize("Legend:", "\033[2m") << "\n";
        
        if (show_confirmed_legend) {
            out << colorize("  † = Confirmed label (verified malicious/clean from intelligence)", "\033[2m") << "\n";
        }
        
        if (show_predicted_legend) {
            out << colorize("  * = Predicted label (suspicious/unknown or not in intelligence database)", "\033[2m") << "\n";
        }
    }
}

void ConsoleFormatter::formatDetectionSummary(const network::AnalysisResult& result, std::ostream& out) {
    out << colorize("Detection Summary", "\033[1;38;2;25;118;210m") << "\n\n";
    
    std::string verdict = result.verdict;
    std::transform(verdict.begin(), verdict.end(), verdict.begin(), ::toupper);
    
    std::ostringstream confidence_str;
    confidence_str << formatPercentage(result.confidence) << "%";
    
    std::string verdict_display = verdict + " (" + confidence_str.str() + ")";
    
    CellStyle verdict_style;
    if (use_colors_) {
        if (result.verdict == "malicious") verdict_style.fg_color = "\033[31;1m";
        else if (result.verdict == "clean") verdict_style.fg_color = "\033[32;1m";
        else if (result.verdict == "suspicious") verdict_style.fg_color = "\033[33;1m";
        else verdict_style.fg_color = "\033[37;1m";
    }
    
    std::ostringstream tags_str;
    for (size_t i = 0; i < result.tags.size(); ++i) {
        if (result.tags[i].find("label:") != 0) {
            if (i > 0 && tags_str.tellp() > 0) tags_str << ", ";
            tags_str << result.tags[i];
        }
    }
    
    TableRenderer table(use_colors_);
    
    TableRow header;
    header.is_header = true;
    header.has_heavy_bottom_border = true;
    header.cells = {
        {"Field", {}, 20, 20},
        {"Value", {}, 70, 70}
    };
    table.addRow(header);
    
    TableRow verdict_row;
    verdict_row.cells = {
        {"Verdict (Confidence)", {}, 20, 20},
        {verdict_display, verdict_style, 70, 70}
    };
    table.addRow(verdict_row);
    
    TableRow filetype_row;
    filetype_row.cells = {
        {"File Type", {}, 20, 20},
        {result.file_type, {}, 70, 70}
    };
    table.addRow(filetype_row);
    
    TableRow md5_row;
    md5_row.cells = {
        {"MD5 Hash", {}, 20, 20},
        {result.file_hashes.count("md5") ? result.file_hashes.at("md5") : "N/A", {}, 70, 70}
    };
    table.addRow(md5_row);
    
    TableRow sha1_row;
    sha1_row.cells = {
        {"SHA1 Hash", {}, 20, 20},
        {result.file_hashes.count("sha1") ? result.file_hashes.at("sha1") : "N/A", {}, 70, 70}
    };
    table.addRow(sha1_row);
    
    TableRow sha256_row;
    sha256_row.cells = {
        {"SHA256 Hash", {}, 20, 20},
        {result.file_hashes.count("sha256") ? result.file_hashes.at("sha256") : "N/A", {}, 70, 70}
    };
    table.addRow(sha256_row);
    
    TableRow signature_row;
    signature_row.cells = {
        {"Signature", {}, 20, 20},
        {result.signature ? *result.signature : "N/A", {}, 70, 70}
    };
    table.addRow(signature_row);
    
    TableRow tags_row;
    tags_row.has_bottom_border = true;
    tags_row.cells = {
        {"Tags", {}, 20, 20},
        {tags_str.str().empty() ? "N/A" : tags_str.str(), {}, 70, 70}
    };
    table.addRow(tags_row);
    
    out << table.render();
}

void ConsoleFormatter::formatIntelligenceStatistics(const network::AnalysisResult& result, std::ostream& out) {
    const auto& stats = result.intelligence.statistics;
    
    out << colorize("Intelligence Statistics", "\033[1;38;2;25;118;210m") << "\n\n";
    
    out << colorize("### Label Distribution", "\033[1m") << "\n\n";
    
    TableRenderer table(use_colors_);
    
    TableRow header;
    header.is_header = true;
    header.has_heavy_bottom_border = true;
    header.cells = {
        {"Classification", {}, 20, 20},
        {"Count", {}, 10, 10},
        {"Max Similarity", {}, 16, 16},
        {"Avg Similarity", {}, 16, 16}
    };
    table.addRow(header);
    
    auto format_similarity = [](const std::optional<float>& sim) -> std::string {
        if (!sim) return "N/A";
        return formatPercentage(*sim) + "%";
    };
    
    auto create_stat_row = [&](const std::string& label, const std::string& color,
                               const network::LabelStatistics& stat, bool is_last) -> TableRow {
        TableRow row;
        row.has_bottom_border = is_last;
        
        CellStyle label_style;
        if (use_colors_) label_style.fg_color = color;
        
        row.cells = {
            {label, label_style, 20, 20},
            {std::to_string(stat.count), {}, 10, 10},
            {format_similarity(stat.max_similarity), {}, 16, 16},
            {format_similarity(stat.avg_similarity), {}, 16, 16}
        };
        return row;
    };
    
    table.addRow(create_stat_row("Malicious", "\033[31m", stats.malicious, false));
    table.addRow(create_stat_row("Suspicious", "\033[33m", stats.suspicious, false));
    table.addRow(create_stat_row("Clean", "\033[32m", stats.clean, false));
    table.addRow(create_stat_row("Unknown", "\033[37m", stats.unknown, true));
    
    out << table.render();
    
    if (!stats.by_signature.empty()) {
        out << "\n" << colorize("### Top Signatures", "\033[1m") << "\n\n";
        
        std::vector<std::pair<std::string, network::SignatureStatistics>> sig_vec(
            stats.by_signature.begin(), stats.by_signature.end()
        );
        
        std::sort(sig_vec.begin(), sig_vec.end(),
            [](const auto& a, const auto& b) {
                return a.second.max_similarity > b.second.max_similarity;
            });
        
        TableRenderer sig_table(use_colors_);
        
        TableRow sig_header;
        sig_header.is_header = true;
        sig_header.has_heavy_bottom_border = true;
        sig_header.cells = {
            {"Signature", {}, 35, 35},
            {"Count", {}, 10, 10},
            {"Max Similarity", {}, 16, 16},
            {"Avg Similarity", {}, 16, 16}
        };
        sig_table.addRow(sig_header);
        
        for (size_t i = 0; i < std::min(sig_vec.size(), size_t(5)); ++i) {
            const auto& [name, sig_stat] = sig_vec[i];
            
            TableRow sig_row;
            sig_row.has_bottom_border = (i == std::min(sig_vec.size(), size_t(5)) - 1);
            sig_row.cells = {
                {name, {}, 35, 35},
                {std::to_string(sig_stat.count), {}, 10, 10},
                {formatPercentage(sig_stat.max_similarity) + "%", {}, 16, 16},
                {formatPercentage(sig_stat.avg_similarity) + "%", {}, 16, 16}
            };
            sig_table.addRow(sig_row);
        }
        
        out << sig_table.render();
    }
}

void ConsoleFormatter::formatAttributeComparison(const network::AnalysisResult& result, std::ostream& out) {
    const auto& similar_samples = result.intelligence.similar_samples;
    if (similar_samples.empty()) return;
    
    bool target_confirmed = hasGroundTruthLabel(result.tags);
    
    out << colorize("Attribute Comparison Matrix", "\033[1;38;2;25;118;210m") << "\n\n";
    
    formatLegend(result, out);
    out << "\n";
    
    TableRenderer table(use_colors_);
    
    TableRow header;
    header.is_header = true;
    header.has_heavy_bottom_border = true;
    
    std::string verdict_upper = result.verdict;
    std::transform(verdict_upper.begin(), verdict_upper.end(), verdict_upper.begin(), ::toupper);
    
    std::string target_header;
    if (target_confirmed) {
        target_header = "Target (" + verdict_upper + "†)";
    } else {
        target_header = "Target (" + verdict_upper + "* " + formatPercentage(result.confidence) + "%)";
    }
    
    CellStyle target_style;
    if (use_colors_) {
        std::string verdict_lower = result.verdict;
        std::transform(verdict_lower.begin(), verdict_lower.end(), verdict_lower.begin(), ::tolower);
        
        if (verdict_lower == "malicious") {
            target_style.bg_color = "\033[48;2;198;40;40m";
        } else if (verdict_lower == "clean") {
            target_style.bg_color = "\033[48;2;0;137;123m";
        } else if (verdict_lower == "suspicious") {
            target_style.bg_color = "\033[48;2;230;81;0m";
        } else {
            target_style.bg_color = "\033[48;2;97;97;97m";
        }
        
        target_style.fg_color = "\033[97m";
        target_style.bold = true;
    }
    
    header.cells.push_back({"Attribute", {}, 30, 30});
    header.cells.push_back({target_header, target_style, 34, 34});
    
    for (size_t i = 0; i < similar_samples.size(); ++i) {
        std::string sample_header = "Sample #" + std::to_string(i + 1);
        std::string label = extractLabelFromTags(similar_samples[i].tags);
        
        CellStyle sample_style;
        if (use_colors_) {
            if (label == "MALICIOUS") sample_style.bg_color = "\033[48;2;198;40;40m";
            else if (label == "SUSPICIOUS") sample_style.bg_color = "\033[48;2;230;81;0m";
            else if (label == "CLEAN") sample_style.bg_color = "\033[48;2;0;137;123m";
            else sample_style.bg_color = "\033[48;2;97;97;97m";
            sample_style.fg_color = "\033[97m";
        }
        
        header.cells.push_back({sample_header, sample_style, 34, 34});
    }
    
    table.addRow(header);
    
    TableRow hash_row;
    hash_row.cells.push_back({"MD5 Hash", {}, 30, 30});
    hash_row.cells.push_back({result.file_hashes.count("md5") ? result.file_hashes.at("md5") : "N/A", {}, 34, 34});
    for (const auto& sample : similar_samples) {
        hash_row.cells.push_back({sample.file_hashes.count("md5") ? sample.file_hashes.at("md5") : "N/A", {}, 34, 34});
    }
    table.addRow(hash_row);
    
    TableRow sim_row;
    sim_row.cells.push_back({"Similarity", {}, 30, 30});
    sim_row.cells.push_back({"Baseline", {}, 34, 34});
    for (const auto& sample : similar_samples) {
        sim_row.cells.push_back({formatPercentage(sample.similarity_score) + "%", {}, 34, 34});
    }
    table.addRow(sim_row);
    
    TableRow label_row;
    label_row.cells.push_back({"Label", {}, 30, 30});
    std::string target_label = extractLabelFromTags(result.tags);
    label_row.cells.push_back({target_label, {}, 34, 34});
    for (const auto& sample : similar_samples) {
        label_row.cells.push_back({extractLabelFromTags(sample.tags), {}, 34, 34});
    }
    table.addRow(label_row);
    
    TableRow sig_row;
    sig_row.cells.push_back({"Signature", {}, 30, 30});
    sig_row.cells.push_back({result.signature ? *result.signature : "N/A", {}, 34, 34});
    for (const auto& sample : similar_samples) {
        sig_row.cells.push_back({sample.signature ? *sample.signature : "N/A", {}, 34, 34});
    }
    table.addRow(sig_row);
    
    TableRow tags_row;
    tags_row.has_heavy_bottom_border = true;
    tags_row.cells.push_back({"Tags", {}, 30, 30});
    
    std::ostringstream target_tags;
    for (size_t i = 0; i < result.tags.size(); ++i) {
        if (result.tags[i].find("label:") != 0) {
            if (i > 0 && target_tags.tellp() > 0) target_tags << ", ";
            target_tags << result.tags[i];
        }
    }
    tags_row.cells.push_back({target_tags.str().empty() ? "N/A" : target_tags.str(), {}, 34, 34});
    
    for (const auto& sample : similar_samples) {
        std::ostringstream sample_tags;
        for (size_t i = 0; i < sample.tags.size(); ++i) {
            if (sample.tags[i].find("label:") != 0) {
                if (i > 0 && sample_tags.tellp() > 0) sample_tags << ", ";
                sample_tags << sample.tags[i];
            }
        }
        tags_row.cells.push_back({sample_tags.str().empty() ? "N/A" : sample_tags.str(), {}, 34, 34});
    }
    table.addRow(tags_row);
    
    auto all_keys = collectAllAttributeKeys(result);
    auto meaningful_keys = filterMeaningfulAttributes(all_keys, result);
    
    for (size_t key_idx = 0; key_idx < meaningful_keys.size(); ++key_idx) {
        const auto& key = meaningful_keys[key_idx];
        
        TableRow attr_row;
        attr_row.cells.push_back({formatAttributeKeyDisplay(key), {}, 30, 30});
        
        auto target_attr = getFlattenedAttribute(
            result.static_attributes_json && !result.static_attributes_json->empty() 
                ? nlohmann::json::parse(*result.static_attributes_json) 
                : nlohmann::json(),
            key
        );
        
        CellStyle target_cell_style;
        attr_row.cells.push_back({formatAttributeValue(target_attr.raw_value), target_cell_style, 34, 34});
        
        for (const auto& sample : similar_samples) {
            auto sample_attr = getFlattenedAttribute(
                sample.static_attributes_json && !sample.static_attributes_json->empty()
                    ? nlohmann::json::parse(*sample.static_attributes_json)
                    : nlohmann::json(),
                key
            );
            
            CellStyle sample_cell_style;
            
            bool target_is_null = target_attr.raw_value.is_null();
            bool sample_is_null = sample_attr.raw_value.is_null();
            
            if (target_is_null && sample_is_null) {
                if (use_colors_) sample_cell_style.bg_color = "\033[48;2;232;245;233m";
            } else if (!target_is_null && !sample_is_null) {
                if (target_attr.raw_value == sample_attr.raw_value) {
                    if (use_colors_) sample_cell_style.bg_color = "\033[48;2;232;245;233m";
                } else {
                    if (use_colors_) sample_cell_style.bg_color = "\033[48;2;255;253;231m";
                }
            } else {
                if (use_colors_) sample_cell_style.bg_color = "\033[48;2;255;253;231m";
            }
            
            attr_row.cells.push_back({formatAttributeValue(sample_attr.raw_value), sample_cell_style, 34, 34});
        }
        
        if (key_idx == meaningful_keys.size() - 1) {
            attr_row.has_bottom_border = true;
        }
        
        table.addRow(attr_row);
    }
    
    out << table.render();
}

void ConsoleFormatter::formatNaturalLanguageReport(const network::AnalysisResult& result, std::ostream& out) {
    if (result.natural_language_report.empty()) return;
    
    out << colorize("Natural Language Report", "\033[1;38;2;25;118;210m") << "\n";
    for (int i = 0; i < 80; ++i) out << "─";
    out << "\n";
    
    MarkdownRenderer renderer(MarkdownOutputFormat::ANSI_CONSOLE, use_colors_);
    std::string rendered = renderer.render(result.natural_language_report);
    out << rendered;
    
    for (int i = 0; i < 80; ++i) out << "─";
    out << "\n";
}

std::set<std::string> ConsoleFormatter::collectAllAttributeKeys(
    const network::AnalysisResult& result
) {
    std::set<std::string> all_keys;
    
    if (result.static_attributes_json && !result.static_attributes_json->empty()) {
        try {
            auto target_attrs = nlohmann::json::parse(*result.static_attributes_json);
            auto flattened = flattenAttributes(target_attrs);
            for (const auto& [key, _] : flattened) {
                all_keys.insert(key);
            }
        } catch (...) {}
    }
    
    for (const auto& sample : result.intelligence.similar_samples) {
        if (sample.static_attributes_json && !sample.static_attributes_json->empty()) {
            try {
                auto sample_attrs = nlohmann::json::parse(*sample.static_attributes_json);
                auto flattened = flattenAttributes(sample_attrs);
                for (const auto& [key, _] : flattened) {
                    all_keys.insert(key);
                }
            } catch (...) {}
        }
    }
    
    return all_keys;
}

std::vector<std::string> ConsoleFormatter::filterMeaningfulAttributes(
    const std::set<std::string>& all_keys,
    const network::AnalysisResult& result
) {
    std::vector<std::string> meaningful;
    
    for (const auto& key : all_keys) {
        int non_null_count = 0;
        int total_count = 1 + static_cast<int>(result.intelligence.similar_samples.size());
        
        auto target_attr = getFlattenedAttribute(
            result.static_attributes_json && !result.static_attributes_json->empty()
                ? nlohmann::json::parse(*result.static_attributes_json)
                : nlohmann::json(),
            key
        );
        if (!target_attr.raw_value.is_null()) non_null_count++;
        
        for (const auto& sample : result.intelligence.similar_samples) {
            auto sample_attr = getFlattenedAttribute(
                sample.static_attributes_json && !sample.static_attributes_json->empty()
                    ? nlohmann::json::parse(*sample.static_attributes_json)
                    : nlohmann::json(),
                key
            );
            if (!sample_attr.raw_value.is_null()) non_null_count++;
        }
        
        float coverage = static_cast<float>(non_null_count) / total_count;
        if (coverage >= 0.5f) {
            meaningful.push_back(key);
        }
    }
    
    return meaningful;
}

std::string ConsoleFormatter::formatAttributeValue(const nlohmann::json& value) {
    if (value.is_null()) return "N/A";
    return formatBasicValue(value);
}

std::string ConsoleFormatter::formatAttributeKeyDisplay(const std::string& key) {
    std::vector<std::string> parts;
    std::stringstream ss(key);
    std::string part;
    
    while (std::getline(ss, part, '.')) {
        std::replace(part.begin(), part.end(), '_', ' ');
        
        if (!part.empty()) {
            part[0] = std::toupper(part[0]);
            for (size_t i = 1; i < part.length(); ++i) {
                if (part[i-1] == ' ' && i < part.length()) {
                    part[i] = std::toupper(part[i]);
                }
            }
        }
        parts.push_back(part);
    }
    
    if (parts.size() > 1) {
        std::string result;
        for (size_t i = 0; i < parts.size(); ++i) {
            if (i > 0) result += " → ";
            result += parts[i];
        }
        return result;
    }
    
    return parts.empty() ? "" : parts[0];
}

std::string ConsoleFormatter::colorize(const std::string& text, const std::string& color_code) {
    if (!use_colors_ || color_code.empty()) {
        return text;
    }
    return color_code + text + "\033[0m";
}

std::string ConsoleFormatter::getVerdictColor(const std::string& verdict) {
    if (!use_colors_) return "";
    
    if (verdict == "malicious") return "\033[38;2;198;40;40m";
    if (verdict == "clean") return "\033[38;2;0;137;123m";
    if (verdict == "suspicious") return "\033[38;2;230;81;0m";
    return "\033[38;2;97;97;97m";
}

std::string ConsoleFormatter::getLabelColor(const std::string& label) {
    if (!use_colors_) return "";
    
    std::string lower_label = label;
    std::transform(lower_label.begin(), lower_label.end(), lower_label.begin(), ::tolower);
    
    if (lower_label == "malicious") return "\033[38;2;198;40;40m";
    if (lower_label == "clean") return "\033[38;2;0;137;123m";
    if (lower_label == "suspicious") return "\033[38;2;230;81;0m";
    return "\033[38;2;97;97;97m";
}

std::string ConsoleFormatter::getSimilarityColor(float similarity) {
    if (!use_colors_) return "";
    
    if (similarity >= 0.8f) return "\033[38;2;198;40;40m";
    if (similarity >= 0.6f) return "\033[38;2;230;81;0m";
    return "\033[37m";
}

FlattenedAttribute ConsoleFormatter::getFlattenedAttribute(
    const nlohmann::json& attrs, 
    const std::string& key
) {
    FlattenedAttribute result;
    result.path = key;
    result.is_present = false;
    result.is_complex = false;
    result.raw_value = nlohmann::json();
    result.display_value = "N/A";
    
    if (attrs.is_null()) return result;
    
    auto flattened = flattenAttributes(attrs);
    auto it = flattened.find(key);
    if (it != flattened.end()) {
        return it->second;
    }
    
    return result;
}

}
}