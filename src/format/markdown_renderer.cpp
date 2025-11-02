#include "semantics_av/format/markdown_renderer.hpp"
#include <cstring>
#include <sstream>

namespace semantics_av {
namespace format {

MarkdownRenderer::MarkdownRenderer(MarkdownOutputFormat format, bool use_colors) 
    : format_(format), use_colors_(use_colors) {
    resetState();
}

void MarkdownRenderer::resetState() {
    output_.clear();
    heading_level_ = 0;
    in_code_block_ = false;
    in_emphasis_ = false;
    in_strong_ = false;
    list_level_ = 0;
    in_list_item_ = false;
    need_list_item_newline_ = false;
}

std::string MarkdownRenderer::render(const std::string& markdown) {
    resetState();
    
    if (format_ == MarkdownOutputFormat::HTML) {
        unsigned int parser_flags = MD_FLAG_TABLES | 
                                    MD_FLAG_STRIKETHROUGH | 
                                    MD_FLAG_TASKLISTS;
        
        unsigned int renderer_flags = 0;
        
        int result = md_html(
            markdown.c_str(),
            static_cast<MD_SIZE>(markdown.length()),
            htmlOutputCallback,
            this,
            parser_flags,
            renderer_flags
        );
        
        if (result != 0) {
            return "<p>Error rendering markdown content.</p>";
        }
    } else {
        MD_PARSER parser = {
            0,
            MD_FLAG_TABLES | MD_FLAG_STRIKETHROUGH | MD_FLAG_TASKLISTS,
            enterBlockCallback,
            leaveBlockCallback,
            enterSpanCallback,
            leaveSpanCallback,
            textCallback,
            nullptr,
            nullptr
        };
        
        md_parse(markdown.c_str(), static_cast<MD_SIZE>(markdown.length()), &parser, this);
    }
    
    return output_;
}

void MarkdownRenderer::htmlOutputCallback(const MD_CHAR* text, MD_SIZE size, void* userdata) {
    auto* renderer = static_cast<MarkdownRenderer*>(userdata);
    renderer->output_.append(text, size);
}

int MarkdownRenderer::enterBlockCallback(MD_BLOCKTYPE type, void* detail, void* userdata) {
    auto* renderer = static_cast<MarkdownRenderer*>(userdata);
    return renderer->enterBlock(type, detail);
}

int MarkdownRenderer::leaveBlockCallback(MD_BLOCKTYPE type, void* detail, void* userdata) {
    auto* renderer = static_cast<MarkdownRenderer*>(userdata);
    return renderer->leaveBlock(type, detail);
}

int MarkdownRenderer::enterSpanCallback(MD_SPANTYPE type, void* detail, void* userdata) {
    auto* renderer = static_cast<MarkdownRenderer*>(userdata);
    return renderer->enterSpan(type, detail);
}

int MarkdownRenderer::leaveSpanCallback(MD_SPANTYPE type, void* detail, void* userdata) {
    auto* renderer = static_cast<MarkdownRenderer*>(userdata);
    return renderer->leaveSpan(type, detail);
}

int MarkdownRenderer::textCallback(MD_TEXTTYPE type, const MD_CHAR* text, MD_SIZE size, void* userdata) {
    auto* renderer = static_cast<MarkdownRenderer*>(userdata);
    return renderer->text(type, text, size);
}

int MarkdownRenderer::enterBlock(MD_BLOCKTYPE type, void* detail) {
    switch (type) {
        case MD_BLOCK_H: {
            auto* h = static_cast<MD_BLOCK_H_DETAIL*>(detail);
            heading_level_ = h->level;
            output_ += "\n";
            if (use_colors_) {
                if (h->level == 1) {
                    output_ += "\033[1;34m";
                } else if (h->level == 2) {
                    output_ += "\033[1;36m";
                } else {
                    output_ += "\033[1;37m";
                }
            }
            break;
        }
        case MD_BLOCK_CODE: {
            in_code_block_ = true;
            output_ += "\n";
            if (use_colors_) {
                output_ += "\033[48;5;235m\033[38;5;150m";
            }
            break;
        }
        case MD_BLOCK_P:
            if (list_level_ == 0) {
                output_ += "\n";
            }
            break;
        case MD_BLOCK_UL:
        case MD_BLOCK_OL:
            list_level_++;
            if (list_level_ == 1) {
                output_ += "\n";
            }
            break;
        case MD_BLOCK_LI: {
            in_list_item_ = true;
            need_list_item_newline_ = false;
            std::string indent((list_level_ - 1) * 2, ' ');
            output_ += indent;
            if (use_colors_) {
                output_ += "\033[1;33m•\033[0m ";
            } else {
                output_ += "• ";
            }
            if (in_strong_) output_ += "\033[1m";
            if (in_emphasis_) output_ += "\033[3m";
            break;
        }
        case MD_BLOCK_QUOTE:
            output_ += "\n";
            if (use_colors_) {
                output_ += "\033[2;37m│ ";
            } else {
                output_ += "│ ";
            }
            break;
        case MD_BLOCK_HR:
            output_ += "\n";
            if (use_colors_) {
                output_ += "\033[2m";
            }
            for (int i = 0; i < 60; ++i) output_ += "─";
            if (use_colors_) {
                output_ += "\033[0m";
            }
            output_ += "\n";
            break;
        case MD_BLOCK_TABLE:
            output_ += "\n";
            break;
        case MD_BLOCK_THEAD:
            break;
        case MD_BLOCK_TBODY:
            break;
        case MD_BLOCK_TR:
            break;
        case MD_BLOCK_TH:
            if (use_colors_) {
                output_ += "\033[1m";
            }
            break;
        case MD_BLOCK_TD:
            break;
        default:
            break;
    }
    
    return 0;
}

int MarkdownRenderer::leaveBlock(MD_BLOCKTYPE type, void* detail) {
    switch (type) {
        case MD_BLOCK_H:
            if (use_colors_) {
                output_ += "\033[0m";
            }
            output_ += "\n";
            heading_level_ = 0;
            break;
        case MD_BLOCK_CODE:
            if (use_colors_) {
                output_ += "\033[0m";
            }
            output_ += "\n";
            in_code_block_ = false;
            break;
        case MD_BLOCK_P:
            if (list_level_ == 0) {
                output_ += "\n";
            } else if (in_list_item_) {
                need_list_item_newline_ = true;
            }
            break;
        case MD_BLOCK_UL:
        case MD_BLOCK_OL:
            list_level_--;
            if (list_level_ == 0) {
                output_ += "\n";
            }
            break;
        case MD_BLOCK_LI:
            if (need_list_item_newline_ || output_.back() != '\n') {
                output_ += "\n";
            }
            in_list_item_ = false;
            need_list_item_newline_ = false;
            break;
        case MD_BLOCK_QUOTE:
            if (use_colors_) {
                output_ += "\033[0m";
            }
            output_ += "\n";
            break;
        case MD_BLOCK_TABLE:
            output_ += "\n";
            break;
        case MD_BLOCK_THEAD:
            break;
        case MD_BLOCK_TBODY:
            break;
        case MD_BLOCK_TR:
            output_ += "\n";
            break;
        case MD_BLOCK_TH:
            if (use_colors_) {
                output_ += "\033[0m";
            }
            output_ += " ";
            break;
        case MD_BLOCK_TD:
            output_ += " ";
            break;
        default:
            break;
    }
    
    return 0;
}

int MarkdownRenderer::enterSpan(MD_SPANTYPE type, void* detail) {
    if (!use_colors_) {
        return 0;
    }
    
    switch (type) {
        case MD_SPAN_STRONG:
            output_ += "\033[1m";
            in_strong_ = true;
            break;
        case MD_SPAN_EM:
            output_ += "\033[3m";
            in_emphasis_ = true;
            break;
        case MD_SPAN_CODE:
            if (!in_code_block_) {
                output_ += "\033[48;5;235m\033[38;5;150m";
            }
            break;
        case MD_SPAN_A:
            output_ += "\033[4;36m";
            break;
        case MD_SPAN_DEL:
            output_ += "\033[9m";
            break;
        default:
            break;
    }
    
    return 0;
}

int MarkdownRenderer::leaveSpan(MD_SPANTYPE type, void* detail) {
    if (!use_colors_) {
        return 0;
    }
    
    switch (type) {
        case MD_SPAN_STRONG:
            output_ += "\033[22m";
            in_strong_ = false;
            break;
        case MD_SPAN_EM:
            output_ += "\033[23m";
            in_emphasis_ = false;
            break;
        case MD_SPAN_CODE:
            if (!in_code_block_) {
                output_ += "\033[0m";
                if (in_strong_) output_ += "\033[1m";
                if (in_emphasis_) output_ += "\033[3m";
            }
            break;
        case MD_SPAN_A:
        case MD_SPAN_DEL:
            output_ += "\033[0m";
            if (in_strong_) output_ += "\033[1m";
            if (in_emphasis_) output_ += "\033[3m";
            break;
        default:
            break;
    }
    
    return 0;
}

int MarkdownRenderer::text(MD_TEXTTYPE type, const MD_CHAR* text, MD_SIZE size) {
    switch (type) {
        case MD_TEXT_NORMAL:
        case MD_TEXT_CODE:
            appendAnsiText(text, size);
            break;
        case MD_TEXT_BR:
        case MD_TEXT_SOFTBR:
            output_ += "\n";
            if (in_list_item_) {
                std::string indent((list_level_ - 1) * 2, ' ');
                output_ += indent + "  ";
            }
            break;
        case MD_TEXT_NULLCHAR:
            break;
        case MD_TEXT_ENTITY:
            appendAnsiText(text, size);
            break;
        default:
            break;
    }
    
    return 0;
}

void MarkdownRenderer::appendAnsiText(const MD_CHAR* text, MD_SIZE size) {
    output_.append(text, size);
}

}}