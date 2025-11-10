#pragma once

#include "types.hpp"
#include <string>
#include <filesystem>
#include <sys/types.h>
#include <unistd.h>

namespace semantics_av {
namespace common {

class PrivilegeManager {
public:
    PrivilegeManager();
    ~PrivilegeManager();
    
    bool initializeWithRoot();
    bool dropPrivileges(const std::string& username = "semantics-av-daemon");
    bool createUser(const std::string& username, const std::string& group = "");
    
    SecurityLevel getCurrentLevel() const;
    bool canBindPrivilegedPorts() const;
    bool canCreateUnixSocket(const std::string& path) const;
    
    bool setupChroot(const std::string& root_path);
    bool setupSeccompFilter();
    
    static bool canSafelyWriteConfig(const std::string& dir);
    static bool checkFileOwnership(const std::string& path, uid_t expected_uid);

private:
    SecurityLevel current_level_;
    bool chrooted_;
    
    bool setupCapabilities();
    bool validateUsername(const std::string& username) const;
    bool setUserAndGroup(const std::string& username);
    void logPrivilegeChange(SecurityLevel from, SecurityLevel to);
};

}}