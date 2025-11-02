#pragma once

#include <string>
#include <md4c.h>
#include <md4c-html.h>

namespace semantics_av {
namespace format {

enum class MarkdownOutputFormat {
    HTML,
    ANSI_CONSOLE
};

class MarkdownRenderer {
public:
    explicit MarkdownRenderer(MarkdownOutputFormat format = MarkdownOutputFormat::HTML, bool use_colors = true);
    
    std::string render(const std::string& markdown);

private:
    MarkdownOutputFormat format_;
    bool use_colors_;
    std::string output_;
    
    int heading_level_;
    bool in_code_block_;
    bool in_emphasis_;
    bool in_strong_;
    int list_level_;
    bool in_list_item_;
    bool need_list_item_newline_;
    
    void resetState();
    
    static int enterBlockCallback(MD_BLOCKTYPE type, void* detail, void* userdata);
    static int leaveBlockCallback(MD_BLOCKTYPE type, void* detail, void* userdata);
    static int enterSpanCallback(MD_SPANTYPE type, void* detail, void* userdata);
    static int leaveSpanCallback(MD_SPANTYPE type, void* detail, void* userdata);
    static int textCallback(MD_TEXTTYPE type, const MD_CHAR* text, MD_SIZE size, void* userdata);
    
    int enterBlock(MD_BLOCKTYPE type, void* detail);
    int leaveBlock(MD_BLOCKTYPE type, void* detail);
    int enterSpan(MD_SPANTYPE type, void* detail);
    int leaveSpan(MD_SPANTYPE type, void* detail);
    int text(MD_TEXTTYPE type, const MD_CHAR* text, MD_SIZE size);
    
    void appendAnsiText(const MD_CHAR* text, MD_SIZE size);
    
    static void htmlOutputCallback(const MD_CHAR* text, MD_SIZE size, void* userdata);
};

}}