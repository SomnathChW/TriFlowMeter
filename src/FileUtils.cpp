// TriFlowMeter - High-Performance Network Flow Analyzer
// Copyright (c) 2026 Somnath Chowdhury (github.com/SomnathChW). All rights reserved.
// Licensed under GPL-3.0
// See LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.html

#include "FileUtils.h"

#include <filesystem>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

void fixOwnershipIfSudo(const std::string& path, bool is_directory) {
#ifndef _WIN32
    const char* sudo_uid_str = std::getenv("SUDO_UID");
    const char* sudo_gid_str = std::getenv("SUDO_GID");
    
    if (sudo_uid_str && sudo_gid_str && fs::exists(path)) {
        try {
            uid_t uid = std::stoi(sudo_uid_str);
            gid_t gid = std::stoi(sudo_gid_str);
            
            if (chown(path.c_str(), uid, gid) != 0) {
                // Best effort only; continue even if ownership update fails.
            }
            
            if (is_directory) {
                // Directory: drwxr-xr-x (755)
                fs::permissions(path, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | 
                                           fs::perms::others_read | fs::perms::others_exec, 
                               fs::perm_options::replace);
            } else {
                // File: -rw-r--r-- (644)
                fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write | 
                                           fs::perms::group_read | fs::perms::others_read, 
                               fs::perm_options::replace);
            }
        } catch (...) {
            // If something fails, continue anyway
        }
    }
#endif
}
