#include "semantics_av/common/security.hpp"
#include "semantics_av/common/logger.hpp"
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <cstring>
#include <cerrno>
#include <filesystem>

namespace semantics_av {
namespace common {

PrivilegeManager::PrivilegeManager() 
    : current_level_(SecurityLevel::ROOT), chrooted_(false) {
    if (getuid() != 0) {
        current_level_ = SecurityLevel::USER;
    }
}

PrivilegeManager::~PrivilegeManager() = default;

bool PrivilegeManager::initializeWithRoot() {
    if (getuid() != 0) {
        Logger::instance().error("[Security] Not running as root");
        return false;
    }
    
    current_level_ = SecurityLevel::ROOT;
    Logger::instance().info("[Security] Initialized with root | uid=0");
    return true;
}

bool PrivilegeManager::dropPrivileges(const std::string& username) {
    if (!validateUsername(username)) {
        return false;
    }
    
    if (current_level_ == SecurityLevel::USER || current_level_ == SecurityLevel::RESTRICTED) {
        Logger::instance().warn("[Security] Privileges already dropped");
        return true;
    }
    
    uid_t old_uid = getuid();
    gid_t old_gid = getgid();
    
    if (!setUserAndGroup(username)) {
        return false;
    }
    
    current_level_ = SecurityLevel::USER;
    
    Logger::instance().info("[Security] Privileges dropped | from_uid={} | to_uid={} | from_gid={} | to_gid={} | user={}", 
                           old_uid, getuid(), old_gid, getgid(), username);
    
    return true;
}

bool PrivilegeManager::createUser(const std::string& username, const std::string& group) {
    if (getuid() != 0) {
        Logger::instance().error("[Security] Need root to create user");
        return false;
    }
    
    struct passwd* pw = getpwnam(username.c_str());
    if (pw != nullptr) {
        Logger::instance().debug("[Security] User exists | user={}", username);
        return true;
    }
    
    std::string cmd = "useradd --system --shell /bin/false --home /nonexistent " + username;
    int result = system(cmd.c_str());
    
    if (result != 0) {
        Logger::instance().error("[Security] User creation failed | user={} | error={}", 
                                username, strerror(errno));
        return false;
    }
    
    Logger::instance().info("[Security] User created | user={}", username);
    return true;
}

SecurityLevel PrivilegeManager::getCurrentLevel() const {
    return current_level_;
}

bool PrivilegeManager::canBindPrivilegedPorts() const {
    return current_level_ == SecurityLevel::ROOT || 
           current_level_ == SecurityLevel::PRIVILEGED;
}

bool PrivilegeManager::canCreateUnixSocket(const std::string& path) const {
    std::filesystem::path socket_path(path);
    std::filesystem::path parent = socket_path.parent_path();
    
    return access(parent.c_str(), W_OK) == 0;
}

bool PrivilegeManager::setupChroot(const std::string& root_path) {
    if (chrooted_) {
        Logger::instance().warn("[Security] Already chrooted");
        return true;
    }
    
    if (chroot(root_path.c_str()) != 0) {
        Logger::instance().error("[Security] Chroot failed | path={} | error={}", 
                                root_path, strerror(errno));
        return false;
    }
    
    if (chdir("/") != 0) {
        Logger::instance().error("[Security] Chdir after chroot failed | error={}", strerror(errno));
        return false;
    }
    
    chrooted_ = true;
    Logger::instance().info("[Security] Chrooted | path={}", root_path);
    return true;
}

bool PrivilegeManager::setupSeccompFilter() {
    Logger::instance().debug("[Security] Seccomp not available in this build");
    return true;
}

bool PrivilegeManager::canSafelyWriteConfig(const std::string& dir) {
    if (access(dir.c_str(), W_OK) != 0) {
        return false;
    }
    
    struct stat st;
    if (stat(dir.c_str(), &st) != 0) {
        return false;
    }
    
    uid_t current_uid = getuid();
    
    if (st.st_uid == current_uid) {
        return true;
    }
    
    if (current_uid == 0) {
        return true;
    }
    
    return false;
}

bool PrivilegeManager::checkFileOwnership(const std::string& path, uid_t expected_uid) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        return false;
    }
    
    return st.st_uid == expected_uid;
}

bool PrivilegeManager::validateUsername(const std::string& username) const {
    if (username.empty()) {
        Logger::instance().error("[Security] Empty username");
        return false;
    }
    
    if (username.length() > 32) {
        Logger::instance().error("[Security] Username too long | user={}", username);
        return false;
    }
    
    for (char c : username) {
        if (!std::isalnum(c) && c != '-' && c != '_') {
            Logger::instance().error("[Security] Invalid character in username | char={}", c);
            return false;
        }
    }
    
    return true;
}

bool PrivilegeManager::setUserAndGroup(const std::string& username) {
    struct passwd* pw = getpwnam(username.c_str());
    if (pw == nullptr) {
        Logger::instance().error("[Security] User not found | user={}", username);
        return false;
    }
    
    if (setgid(pw->pw_gid) != 0) {
        Logger::instance().error("[Security] setgid failed | gid={} | error={}", 
                                pw->pw_gid, strerror(errno));
        return false;
    }
    
    if (setuid(pw->pw_uid) != 0) {
        Logger::instance().error("[Security] setuid failed | uid={} | error={}", 
                                pw->pw_uid, strerror(errno));
        return false;
    }
    
    if (setuid(0) == 0) {
        Logger::instance().error("[Security] Privilege drop verification failed - still have root");
        return false;
    }
    
    return true;
}

void PrivilegeManager::logPrivilegeChange(SecurityLevel from, SecurityLevel to) {
    auto to_string = [](SecurityLevel level) -> std::string {
        switch (level) {
            case SecurityLevel::ROOT: return "ROOT";
            case SecurityLevel::PRIVILEGED: return "PRIVILEGED";
            case SecurityLevel::USER: return "USER";
            case SecurityLevel::RESTRICTED: return "RESTRICTED";
            default: return "UNKNOWN";
        }
    };
    
    Logger::instance().info("[Security] Level changed | from={} | to={}", to_string(from), to_string(to));
}

}}