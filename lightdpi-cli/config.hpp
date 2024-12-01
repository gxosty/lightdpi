#pragma once

#include <filesystem>
#include <lightdpi/params.hpp>

namespace fs = std::filesystem;

void load_from_config(fs::path config_path, ldpi::Params& params);