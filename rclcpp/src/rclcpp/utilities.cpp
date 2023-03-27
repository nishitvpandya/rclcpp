// Copyright 2015 Open Source Robotics Foundation, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "rclcpp/utilities.hpp"

#include <chrono>
#include <functional>
#include <string>
#include <vector>

#include "./signal_handler.hpp"
#include "rclcpp/contexts/default_context.hpp"
#include "rclcpp/detail/utilities.hpp"
#include "rclcpp/exceptions.hpp"

#include "rcl/error_handling.h"
#include "rcl/rcl.h"
#include "rcl/init_options.h"
#include "rmw/init_options.h"

#include "rcl/arguments.h"
#include "rcl/log_level.h"
#include "rcl_yaml_param_parser/types.h"

#include "rcl/allocator.h"
#include "rcl/macros.h"
#include "rcl/remap.h"
#include "rcl/types.h"
#include "rcl/visibility_control.h"


#include <iostream>

// #include "rmw/init.h"


struct rcl_arguments_impl_s
{
  /// Array of indices to unknown ROS specific arguments.
  int * unparsed_ros_args;
  /// Length of unparsed_ros_args.
  int num_unparsed_ros_args;

  /// Array of indices to non-ROS arguments.
  int * unparsed_args;
  /// Length of unparsed_args.
  int num_unparsed_args;

  /// Parameter override rules parsed from arguments.
  rcl_params_t * parameter_overrides;

  /// Array of yaml parameter file paths
  char ** parameter_files;
  /// Length of parameter_files.
  int num_param_files_args;

  /// Array of rules for name remapping.
  rcl_remap_t * remap_rules;
  /// Length of remap_rules.
  int num_remap_rules;

  /// Log levels parsed from arguments.
  rcl_log_levels_t log_levels;
  /// A file used to configure the external logging library
  char * external_log_config_file;
  /// A boolean value indicating if the standard out handler should be used for log output
  bool log_stdout_disabled;
  /// A boolean value indicating if the rosout topic handler should be used for log output
  bool log_rosout_disabled;
  /// A boolean value indicating if the external lib handler should be used for log output
  bool log_ext_lib_disabled;

  /// Enclave to be used.
  char * enclave;

  /// Allocator used to allocate objects in this struct
  rcl_allocator_t allocator;
};
typedef enum rcl_remap_type_t
{
  RCL_UNKNOWN_REMAP = 0,
  RCL_TOPIC_REMAP = 1u << 0,
  RCL_SERVICE_REMAP = 1u << 1,
  RCL_NODENAME_REMAP = 1u << 2,
  RCL_NAMESPACE_REMAP = 1u << 3
} rcl_remap_type_t;

struct rcl_remap_impl_s
{
  /// Bitmask indicating what type of rule this is.
  rcl_remap_type_t type;
  /// A node name that this rule is limited to, or NULL if it applies to any node.
  char * node_name;
  /// Match portion of a rule, or NULL if node name or namespace replacement.
  char * match;
  /// Replacement portion of a rule.
  char * replacement;

  /// Allocator used to allocate objects in this struct
  rcl_allocator_t allocator;
};


namespace rclcpp
{

void difc_init(const std::string & self_enclave_name);

void
init(
  int argc,
  char const * const * argv,
  const InitOptions & init_options,
  SignalHandlerOptions signal_handler_options)
{
  using rclcpp::contexts::get_global_default_context;
  get_global_default_context()->init(argc, argv, init_options);
  // Install the signal handlers.
  install_signal_handlers(signal_handler_options);
  std::string self_enclave_name_checked;
  try {
    std::string self_enclave_name_temp = rclcpp::contexts::get_global_default_context() -> get_rcl_context() -> global_arguments.impl -> enclave;
    std::string self_enclave_name(self_enclave_name_temp.begin() + 1, self_enclave_name_temp.end());
    self_enclave_name_checked = self_enclave_name;
  } catch(...)
  {
    self_enclave_name_checked = "";
  }
  difc_init(self_enclave_name_checked);
}

bool
install_signal_handlers(SignalHandlerOptions signal_handler_options)
{
  return SignalHandler::get_global_signal_handler().install(signal_handler_options);
}

bool
signal_handlers_installed()
{
  return SignalHandler::get_global_signal_handler().is_installed();
}

SignalHandlerOptions
get_current_signal_handler_options()
{
  return SignalHandler::get_global_signal_handler().get_current_signal_handler_options();
}


bool
uninstall_signal_handlers()
{
  return SignalHandler::get_global_signal_handler().uninstall();
}

static
std::vector<std::string>
_remove_ros_arguments(
  char const * const * argv,
  const rcl_arguments_t * args,
  rcl_allocator_t alloc)
{
  rcl_ret_t ret;
  int nonros_argc = 0;
  const char ** nonros_argv = NULL;

  ret = rcl_remove_ros_arguments(
    argv,
    args,
    alloc,
    &nonros_argc,
    &nonros_argv);

  if (RCL_RET_OK != ret || nonros_argc < 0) {
    // Not using throw_from_rcl_error, because we may need to append deallocation failures.
    exceptions::RCLError exc(ret, rcl_get_error_state(), "");
    rcl_reset_error();
    if (NULL != nonros_argv) {
      alloc.deallocate(nonros_argv, alloc.state);
    }
    throw exc;
  }

  std::vector<std::string> return_arguments(static_cast<size_t>(nonros_argc));

  for (size_t ii = 0; ii < static_cast<size_t>(nonros_argc); ++ii) {
    return_arguments[ii] = std::string(nonros_argv[ii]);
  }

  if (NULL != nonros_argv) {
    alloc.deallocate(nonros_argv, alloc.state);
  }

  return return_arguments;
}

std::vector<std::string>
init_and_remove_ros_arguments(
  int argc,
  char const * const * argv,
  const InitOptions & init_options)
{
  init(argc, argv, init_options);

  using rclcpp::contexts::get_global_default_context;
  auto rcl_context = get_global_default_context()->get_rcl_context();
  return _remove_ros_arguments(argv, &(rcl_context->global_arguments), rcl_get_default_allocator());
}

std::vector<std::string>
remove_ros_arguments(int argc, char const * const * argv)
{
  rcl_allocator_t alloc = rcl_get_default_allocator();
  rcl_arguments_t parsed_args = rcl_get_zero_initialized_arguments();

  rcl_ret_t ret;

  ret = rcl_parse_arguments(argc, argv, alloc, &parsed_args);
  if (RCL_RET_OK != ret) {
    exceptions::throw_from_rcl_error(ret, "failed to parse arguments");
  }

  std::vector<std::string> return_arguments;
  try {
    return_arguments = _remove_ros_arguments(argv, &parsed_args, alloc);
  } catch (exceptions::RCLError & exc) {
    if (RCL_RET_OK != rcl_arguments_fini(&parsed_args)) {
      exc.formatted_message += std::string(
        ", failed also to cleanup parsed arguments, leaking memory: ") +
        rcl_get_error_string().str;
      rcl_reset_error();
    }
    throw exc;
  }

  ret = rcl_arguments_fini(&parsed_args);
  if (RCL_RET_OK != ret) {
    exceptions::throw_from_rcl_error(
      ret, "failed to cleanup parsed arguments, leaking memory");
  }

  return return_arguments;
}

bool
ok(Context::SharedPtr context)
{
  using rclcpp::contexts::get_global_default_context;
  if (nullptr == context) {
    context = get_global_default_context();
  }
  return context->is_valid();
}

bool
shutdown(Context::SharedPtr context, const std::string & reason)
{
  using rclcpp::contexts::get_global_default_context;
  auto default_context = get_global_default_context();
  if (nullptr == context) {
    context = default_context;
  }
  bool ret = context->shutdown(reason);
  if (context == default_context) {
    uninstall_signal_handlers();
  }
  return ret;
}

void
on_shutdown(std::function<void()> callback, Context::SharedPtr context)
{
  using rclcpp::contexts::get_global_default_context;
  if (nullptr == context) {
    context = get_global_default_context();
  }
  context->on_shutdown(callback);
}

bool
sleep_for(const std::chrono::nanoseconds & nanoseconds, Context::SharedPtr context)
{
  using rclcpp::contexts::get_global_default_context;
  if (nullptr == context) {
    context = get_global_default_context();
  }
  return context->sleep_for(nanoseconds);
}

const char *
get_c_string(const char * string_in)
{
  return string_in;
}

const char *
get_c_string(const std::string & string_in)
{
  return string_in.c_str();
}

std::vector<const char *>
get_c_vector_string(const std::vector<std::string> & strings_in)
{
  std::vector<const char *> cstrings;
  cstrings.reserve(strings_in.size());

  for (size_t i = 0; i < strings_in.size(); ++i) {
    cstrings.push_back(strings_in[i].c_str());
  }

  return cstrings;
}

}  // namespace rclcpp
