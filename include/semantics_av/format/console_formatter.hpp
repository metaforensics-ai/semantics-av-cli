#pragma once

#include "../network/client.hpp"
#include "common_types.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include <set>

namespace semantics_av {
namespace format {

struct BoxChars {
    std::string horizontal = "─";
    std::string vertical = "│";
    std::string top_left = "┌";
    std::string top_right = "┐";
    std::string bottom_left = "└";
    std::string bottom_right = "┘";
    std::string cross = "┼";
    std::string t_down = "┬";
    std::string t_up = "┴";
    std::string t_right = "├";
    std::string t_left = "┤";
    std::string heavy_horizontal = "━";
    std::string heavy_vertical = "┃";
    std::string heavy_top_left = "┏";
    std::string heavy_top_right = "┓";
    std::string heavy_bottom_left = "┗";
    std::string heavy_bottom_right = "┛";
};

struct CellStyle {
    std::string bg_color;
    std::string fg_color;
    bool bold = false;
};

struct TableCell {
    std::string content;
    CellStyle style;
    int min_width = 0;
    int max_width = 0;
};

struct TableRow {
    std::vector<TableCell> cells;
    bool is_header = false;
    bool has_bottom_border = false;
    bool has_heavy_bottom_border = false;
};

class TableRenderer {
public:
    explicit TableRenderer(bool use_colors);
    
    void addRow(const TableRow& row);
    std::string render();
    
private:
    bool use_colors_;
    std::vector<TableRow> rows_;
    std::vector<int> column_widths_;
    BoxChars box_;
    
    void calculateColumnWidths();
    std::vector<std::string> wrapText(const std::string& text, int width);
    std::string extractChunk(const std::string& text, size_t& pos, int max_width);
    std::string renderCell(const TableCell& cell, int width, const std::vector<std::string>& lines, size_t line_index);
    std::string renderBorder(bool is_top, bool is_bottom, bool is_heavy);
    std::string applyStyle(const std::string& text, const CellStyle& style);
    std::string colorize(const std::string& text, const std::string& color_code);
    std::string repeatString(const std::string& str, int count);
    int getDisplayWidth(const std::string& text);
};

class ConsoleFormatter {
public:
    ConsoleFormatter(bool use_colors = true);
    
    void format(const network::AnalysisResult& result, std::ostream& out);

private:
    bool use_colors_;
    
    void formatLegend(const network::AnalysisResult& result, std::ostream& out);
    void formatDetectionSummary(const network::AnalysisResult& result, std::ostream& out);
    void formatIntelligenceStatistics(const network::AnalysisResult& result, std::ostream& out);
    void formatAttributeComparison(const network::AnalysisResult& result, std::ostream& out);
    void formatNaturalLanguageReport(const network::AnalysisResult& result, std::ostream& out);
    
    std::set<std::string> collectAllAttributeKeys(const network::AnalysisResult& result);
    std::vector<std::string> filterMeaningfulAttributes(const std::set<std::string>& all_keys, const network::AnalysisResult& result);
    
    std::string formatAttributeValue(const nlohmann::json& value);
    std::string formatAttributeKeyDisplay(const std::string& key);
    
    std::string colorize(const std::string& text, const std::string& color_code);
    std::string getVerdictColor(const std::string& verdict);
    std::string getLabelColor(const std::string& label);
    std::string getSimilarityColor(float similarity);
    
    FlattenedAttribute getFlattenedAttribute(const nlohmann::json& attrs, const std::string& key);
};

}
}