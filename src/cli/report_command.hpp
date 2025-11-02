#pragma once

#include "main_command.hpp"
#include "semantics_av/network/client.hpp"
#include <CLI/CLI.hpp>
#include <string>

namespace semantics_av {
namespace cli {

class ReportCommand : public MainCommand {
public:
    ReportCommand();
    
    void setup(CLI::App* subcommand);
    bool wasCalled() const;
    int execute();

private:
    bool was_called_;
    
    CLI::App* list_cmd_;
    std::string list_sort_;
    std::string list_filter_;
    size_t list_limit_;
    std::string list_format_;
    
    CLI::App* show_cmd_;
    std::string show_report_id_;
    std::string show_format_;
    
    CLI::App* convert_cmd_;
    std::string convert_report_id_;
    std::string convert_format_;
    std::string convert_output_;
    
    CLI::App* delete_cmd_;
    std::string delete_report_id_;
    int delete_older_than_;
    std::string delete_verdict_;
    bool delete_confirm_;
    
    CLI::App* info_cmd_;
    std::string info_report_id_;
    
    CLI::App* stats_cmd_;
    
    int executeList();
    int executeShow();
    int executeConvert();
    int executeDelete();
    int executeInfo();
    int executeStats();
    
    bool matchPattern(const std::string& text, const std::string& pattern) const;
};

}}