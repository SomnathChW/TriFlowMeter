
/*
 * TriFlowMeter - High-Performance Network Flow Analyzer
 * Copyright (C) 2026 Somnath Chowdhury
 * Author: Somnath Chowdhury (http://github.com/SomnathChW)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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
