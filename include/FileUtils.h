#ifndef FILEUTILS_H
#define FILEUTILS_H

#include <string>

/**
 * Fix file/directory ownership and permissions if running with sudo.
 * Restores ownership to the original user and sets appropriate permissions.
 * 
 * @param path Path to the file or directory to fix
 * @param is_directory True if path is a directory, false if it's a file
 */
void fixOwnershipIfSudo(const std::string& path, bool is_directory = false);

#endif // FILEUTILS_H
